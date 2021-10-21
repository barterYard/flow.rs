use std::intrinsics::transmute;
use std::{future::Future, pin::Pin, time::Duration};

use std::task::Poll;

use crate::client::FlowClient;
use crate::TransactionStatus;
use crate::{client::GrpcClient, GetTransactionRequest, TransactionResultResponse};

/// Repeatedly queries a client about a transaction,
/// yielding the result after it has been sealed or expired.
///
/// If an error occured while making requests, yields Err.
/// If the timeout has reached, yields Ok(None). Otherwise,
/// yields Ok(Some(transaction_result)).
pub struct Finalize<'a, C: GrpcClient<GetTransactionRequest<'a>, TransactionResultResponse>> {
    tx_id: &'a [u8],
    client: &'a mut FlowClient<C>,
    delay: Duration,
    timeout: futures_timer::Delay,
    state: FinalizeState<'a, C>,
}

impl<'a, C: GrpcClient<GetTransactionRequest<'a>, TransactionResultResponse>> Finalize<'a, C> {
    pub fn new(
        tx_id: &'a [u8],
        client: &'a mut FlowClient<C>,
        delay: Duration,
        timeout: Duration,
    ) -> Self {
        let timeout = futures_timer::Delay::new(timeout);
        let fut = client.send(GetTransactionRequest { id: tx_id });

        // transmute PinnedBox<dyn Future + 'a> to PinnedBox<dyn Future + 'static>
        //
        // SAFETY: this is safe since we never leak the future to elsewhere.
        // Since it will always be contained in this structure, and the box is always valid if 'a is valid,
        // and 'a is valid for the entire lifetime of `Self`, the box is valid for the entire lifetime of
        // `Self`
        let fut: Pin<Box<dyn Future<Output = Result<TransactionResultResponse, C::Error>>>> =
            unsafe { transmute(fut) };
        let state = FinalizeState::Request(fut);

        Self {
            tx_id,
            client,
            delay,
            timeout,
            state,
        }
    }
}

impl<'a, C: GrpcClient<GetTransactionRequest<'a>, TransactionResultResponse>> Future
    for Finalize<'a, C>
{
    type Output = Result<Option<TransactionResultResponse>, C::Error>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Self::Output> {
        let this = &mut *self;

        // We haven't made any progress.
        // Returns Poll::Pending if the timeout hasn't been reached.
        macro_rules! pending {
            () => {
                match Pin::new(&mut this.timeout).poll(cx) {
                    Poll::Pending => Poll::Pending,
                    // timeout has reached and we still haven't got
                    Poll::Ready(()) => Poll::Ready(Ok(None)),
                }
            };
        }
        match &mut this.state {
            FinalizeState::Request(df) => match df.as_mut().poll(cx) {
                Poll::Ready(Ok(response)) => {
                    match response.status {
                        TransactionStatus::Sealed | TransactionStatus::Expired => {
                            Poll::Ready(Ok(Some(response)))
                        }
                        // not finalized yet
                        // if the response suggests that the transaction is still ongoing, switch state to delay.
                        _ => {
                            this.state =
                                FinalizeState::Waiting(futures_timer::Delay::new(this.delay));

                            // Poll `self` again, returning if timed out.
                            self.poll(cx)
                        }
                    }
                }
                // If an error occured, return the error.
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => pending!(),
            },
            FinalizeState::Waiting(delay) => match Pin::new(delay).poll(cx) {
                Poll::Ready(()) => {
                    // Send another request.
                    let fut = this.client.send(GetTransactionRequest { id: this.tx_id });
                    // transmute PinnedBox<dyn Future + 'a> to PinnedBox<dyn Future + 'static>
                    //
                    // SAFETY: this is safe since we never leak the future to elsewhere.
                    // Since it will always be contained in this structure, and the box is always valid if 'a is valid,
                    // and 'a is valid for the entire lifetime of `Self`, the box is valid for the entire lifetime of
                    // `Self`
                    let fut: Pin<
                        Box<dyn Future<Output = Result<TransactionResultResponse, C::Error>>>,
                    > = unsafe { transmute(fut) };
                    self.state = FinalizeState::Request(fut);

                    // Poll `self` again, this time on the request.
                    self.poll(cx)
                }
                Poll::Pending => pending!(),
            },
        }
    }
}

enum FinalizeState<'a, C: GrpcClient<GetTransactionRequest<'a>, TransactionResultResponse>> {
    Request(Pin<Box<dyn Future<Output = Result<TransactionResultResponse, C::Error>>>>),
    Waiting(futures_timer::Delay),
}
