//! ## Flow gRPC connections
//!
//! This module contains the `Client` types for gRPC connections.
//!
//! If you wish to customize and build your own client, implement [`GrpcClient`]
//! for your client for input and output types you want to support. If you can
//! support all types, consider using the [`FlowRequest`](crate::requests::FlowRequest)
//! trait to generalize implementations.

use std::error::Error;
use std::future::Future;
use std::pin::Pin;

use http::uri::PathAndQuery;
use http_body::Body;
use otopr::decoding::DecodableMessage;
use otopr::encoding::EncodableMessage;
use tonic::body::BoxBody;
use tonic::client::{Grpc, GrpcService};
use tonic::Request;

use crate::access::*;
use crate::codec::{OtoprCodec, PreEncode};
use crate::entities::{Account, Block, BlockHeader, Collection};
use crate::error::TonicError;
use crate::protobuf::*;
use crate::requests::FlowRequest;
use crate::transaction::{TransactionD, TransactionE};

/// A gRPC client trait.
///
/// Implementors should be generic over the input and output types, but it is not required.
pub trait GrpcClient<I, O> {
    /// The error type of the client.
    type Error: Into<Box<dyn Error + Send + Sync>>;

    /// Sends a request with the client.
    /// Returns a future that evaluates a Result, potentially containing the output.
    fn send<'a>(
        &'a mut self,
        input: I,
    ) -> Pin<Box<dyn Future<Output = Result<O, Self::Error>> + 'a>>;
}

impl<'t, T, I, O> GrpcClient<I, O> for &'t mut T
where
    T: GrpcClient<I, O>,
{
    type Error = T::Error;

    fn send<'a>(
        &'a mut self,
        input: I,
    ) -> Pin<Box<dyn Future<Output = Result<O, Self::Error>> + 'a>> {
        T::send(self, input)
    }
}

/// A gRPC client wrapper. Has utility functions for sending requests.
#[derive(Default, Debug, Clone, Copy)]
pub struct FlowClient<T> {
    inner: T,
}

/// A client that uses the `tonic` gRPC dispatcher which wraps some inner gRPC service.
pub type TonicClient<Service> = Grpc<Service>;

/// A tonic gRPC client.
pub type TonicFlowClient<Service> = FlowClient<TonicClient<Service>>;

/// A tonic gRPC client that uses the `hyper` crate for HTTP transport.
#[cfg(feature = "tonic-transport")]
pub type TonicHyperClient = TonicClient<tonic::transport::Channel>;

/// A flow client that uses `TonicHyperClient` as gRPC client.
#[cfg(feature = "tonic-transport")]
pub type TonicHyperFlowClient = FlowClient<TonicHyperClient>;

/// The return type of sending a request over the gRPC connection.
///
/// This is a future that resolves to a result which contains either the output or an error.
pub type GrpcSendResult<'a, Output> =
    Pin<Box<dyn Future<Output = Result<Output, TonicError>> + 'a>>;

macro_rules! choose {
    ((), ($($empty:tt)*), ($($non_empty:tt)*)) => {
        $($empty)*
    };
    (($($tt:tt)+), ($($empty:tt)*), ($($non_empty:tt)*)) => {
        $($non_empty)*
    };
}

// Simple requests that constructs a request from parameters.
macro_rules! define_requests {
    ($($(#[$meta:meta])* $vis:vis async fn $fn_name:ident$(<($($ttss:tt)*)>)?($($tt:tt)*) $input:ty $(=> $output:ty)? $(where ($($tts:tt)*))? { $expr:expr })+) => {
        $(
            choose! {
                ($($output)?),
                ( // If no return ty
                    $(#[$meta])*
                    $vis fn $fn_name<'grpc, O, $($($ttss)*)?>(&'grpc mut self,$($tt)*) -> Pin<Box<dyn Future<Output = Result<O, Inner::Error>> + 'grpc>>
                        where
                            Inner: GrpcClient< $input, O >,
                            $($($tts)*)?
                    {
                        self.send($expr)
                    }
                ),
                ( // has return ty
                    $(#[$meta])*
                    $vis fn $fn_name<'grpc, $($($ttss)*)?>(&'grpc mut self,$($tt)*) -> Pin<Box<dyn Future<Output = Result< $($output)? , Inner::Error>> + 'grpc>>
                        where
                            Inner: GrpcClient< $input, $($output)? >,
                            $($($tts)*)?
                    {
                        self.send($expr)
                    }
                )
            }
        )+
    }
}

// Requests that `.map()`s the futures before returning.
macro_rules! remapping_requests {
    ($($(#[$meta:meta])* $vis:vis async fn $fn_name:ident$(<($($ttss:tt)*)>)?($($tt:tt)*)
        $input:ty => $output:ty $(where ($($tts:tt)*))? {
            $expr:expr;
            remap = |$paramName:ident| -> $remappedty:ty $remap:block
        })+) => {
        $($(#[$meta])*
        $vis fn $fn_name<'grpc, $($($ttss)*)?>(&'grpc mut self,$($tt)*) ->
            futures_util::future::Map<
                Pin<Box<dyn Future<Output = Result< $output, Inner::Error> > + 'grpc>>,
                fn(Result< $output, Inner::Error >) -> Result< $remappedty, Inner::Error >,
            >
            where
                Inner: GrpcClient< $input, $output >,
                $($($tts)*)?
        {
            fn remap_ok($paramName: $output) -> $remappedty {
                $remap
            }
            fn remap<E>(res: Result< $output, E >) -> Result< $remappedty, E > {
                res.map(remap_ok)
            }
            use futures_util::FutureExt;
            self.send($expr).map(remap::<Inner::Error>)
        })+
    }
}

impl<Inner> FlowClient<Inner> {
    /// Wraps the inner client to gain access to helper functions to send requests.
    #[inline]
    pub const fn new(inner: Inner) -> Self {
        Self { inner }
    }

    /// Retrieve the inner client from this instance.
    #[inline]
    pub fn into_inner(self) -> Inner {
        self.inner
    }

    /// Gets the inner client as a mutable reference.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut Inner {
        &mut self.inner
    }

    /// Sends a request over the client.
    #[inline]
    pub fn send<'a, T, U>(
        &'a mut self,
        input: T,
    ) -> Pin<Box<dyn Future<Output = Result<U, Inner::Error>> + 'a>>
    where
        Inner: GrpcClient<T, U>,
    {
        self.inner.send(input)
    }

    define_requests! {
        /// Sends a ping over the network.
        pub async fn ping() PingRequest => PingResponse {
            PingRequest {}
        }

        /// Retrieves events with the specified type within the specified range.
        pub async fn events_for_height_range<(EventTy)>(ty: EventTy, start_height: u64, end_height: u64) GetEventsForHeightRangeRequest<EventTy> => EventsResponse {
            GetEventsForHeightRangeRequest { ty, start_height, end_height }
        }

        /// Retrieves events with the specified type with the specified block ids.
        pub async fn events_for_blocks_by_ids<(EventTy, BlockIds)>(ty: EventTy, block_ids: BlockIds) GetEventsForBlockIdsRequest<EventTy, BlockIds> => EventsResponse {
            GetEventsForBlockIdsRequest { ty, block_ids }
        }

        /// Executes Cadence script at the latest block and returns the result.
        pub async fn execute_script_at_latest_block<(Script, Arguments)>(script: Script, arguments: Arguments) ExecuteScriptAtLatestBlockRequest<Script, Arguments> => ExecuteScriptResponse {
            ExecuteScriptAtLatestBlockRequest { script, arguments }
        }

        /// Executes Cadence script at a specific block height and returns the result.
        pub async fn execute_script_at_block_id<(BlockId, Script, Arguments)>(block_id: BlockId, script: Script, arguments: Arguments) ExecuteScriptAtBlockIdRequest<BlockId, Script, Arguments> => ExecuteScriptResponse {
            ExecuteScriptAtBlockIdRequest { block_id, script, arguments }
        }

        /// Executes Cadence script at a specific block height and returns the result.
        pub async fn execute_script_at_block_height<(Script, Arguments)>(block_height: u64, script: Script, arguments: Arguments) ExecuteScriptAtBlockHeightRequest<Script, Arguments> => ExecuteScriptResponse {
            ExecuteScriptAtBlockHeightRequest { block_height, script, arguments }
        }

        /// Sends a transaction over the network.
        pub async fn send_transaction<(
            Script,
            Arguments,
            ReferenceBlockId,
            ProposalKeyAddress,
            Payer,
            Authorizers,
            PayloadSignatures,
            EnvelopeSignatures,
        )>(transaction: TransactionE<
            Script,
            Arguments,
            ReferenceBlockId,
            ProposalKeyAddress,
            Payer,
            Authorizers,
            PayloadSignatures,
            EnvelopeSignatures,
        >) SendTransactionRequest<
            Script,
            Arguments,
            ReferenceBlockId,
            ProposalKeyAddress,
            Payer,
            Authorizers,
            PayloadSignatures,
            EnvelopeSignatures,
        > => SendTransactionResponse
        {
            SendTransactionRequest { transaction }
        }

        /// Retrieves a transaction's result by its ID.
        pub async fn transaction_result_by_id<(Id)>(id: Id) GetTransactionRequest<Id> => TransactionResultResponse {
            GetTransactionRequest { id }
        }
    }

    remapping_requests! {
        /// Retrieves a transaction by its ID.
        pub async fn transaction_by_id<(Id)>(id: Id) GetTransactionRequest<Id> => TransactionResponse {
            GetTransactionRequest { id };
            remap = |txn_response| -> TransactionD {
                txn_response.transaction
            }
        }

        /// Retrieves information about an account at the latest block.
        pub async fn account_at_latest_block<(Addr)>(address: Addr) GetAccountAtLatestBlockRequest<Addr> => AccountResponse {
            GetAccountAtLatestBlockRequest { address };
            remap = |acc_response| -> Account {
                acc_response.account
            }
        }

        /// Retrieves information about an account at the specified block height.
        pub async fn account_at_block_height<(Addr)>(address: Addr, block_height: u64) GetAccountAtBlockHeightRequest<Addr> => AccountResponse {
            GetAccountAtBlockHeightRequest { address, block_height };
            remap = |acc_response| -> Account {
                acc_response.account
            }
        }

        /// Retrieves header information of the latest block.
        pub async fn latest_block_header(seal: Seal) GetLatestBlockHeaderRequest => BlockHeaderResponse {
            GetLatestBlockHeaderRequest { seal };
            remap = |header_response| -> BlockHeader {
                header_response.0
            }
        }

        /// Retrieves header information of a block specified by its height.
        pub async fn block_header_by_height(height: u64) GetBlockHeaderByHeightRequest => BlockHeaderResponse {
            GetBlockHeaderByHeightRequest { height };
            remap = |header_response| -> BlockHeader {
                header_response.0
            }
        }

        /// Retrieves header information of a block specified by its ID.
        pub async fn block_header_by_id<(Id)>(id: Id) GetBlockHeaderByIdRequest<Id> => BlockHeaderResponse {
            GetBlockHeaderByIdRequest { id };
            remap = |header_response| -> BlockHeader {
                header_response.0
            }
        }

        /// Retrieves full information of the latest block.
        pub async fn latest_block(seal: Seal) GetLatestBlockRequest => BlockResponse {
            GetLatestBlockRequest { seal };
            remap = |block_response| -> Block {
                block_response.0
            }
        }

        /// Retrieves full information of a block specified by its height.
        pub async fn block_by_height(height: u64) GetBlockByHeightRequest => BlockResponse {
            GetBlockByHeightRequest { height };
            remap = |block_response| -> Block {
                block_response.0
            }
        }

        /// Retrieves full information of a block specified by its ID.
        pub async fn block_by_id<(Id)>(id: Id) GetBlockByIdRequest<Id> => BlockResponse {
            GetBlockByIdRequest { id };
            remap = |block_response| -> Block {
                block_response.0
            }
        }

        /// Retrieves information of a collection specified by its ID.
        pub async fn collection_by_id<(Id)>(id: Id) GetCollectionByIdRequest<Id> => CollectionResponse {
            GetCollectionByIdRequest { id };
            remap = |collection_response| -> Collection {
                collection_response.collection
            }
        }
    }
}

#[cfg(feature = "tonic-transport")]
impl TonicHyperFlowClient {
    /// Connects to a static endpoint URI.
    pub async fn connect_static(uri: &'static str) -> Result<Self, tonic::transport::Error> {
        Self::connect(tonic::transport::Endpoint::from_static(uri)).await
    }

    /// Connects to an endpoint
    pub async fn connect(
        endpoint: tonic::transport::Endpoint,
    ) -> Result<Self, tonic::transport::Error> {
        Ok(Self {
            inner: Grpc::new(endpoint.connect().await?),
        })
    }

    /// Connects to the Mainnet access node provided by Dapper Labs.
    pub async fn mainnet() -> Result<Self, tonic::transport::Error> {
        Self::connect_static("http://access.mainnet.nodes.onflow.org:9000").await
    }

    /// Connects to the Testnet access node provided by Dapper Labs.
    pub async fn testnet() -> Result<Self, tonic::transport::Error> {
        Self::connect_static("http://access.devnet.nodes.onflow.org:9000").await
    }

    /// Connects to a static endpoint URI. Does not connect until we try to send a request.
    ///
    /// Note: You must have entered the tokio runtime context before calling this function.
    /// You can do so by writing the code down below, or it will automatically be entered, if
    /// you have an `.await` before calling this. Consider using the `async` functions instead.
    ///
    /// ```rust,ignore
    /// let handle = tokio::runtime::Handle::current();
    /// handle.enter();
    /// ```
    pub fn connect_static_lazy(uri: &'static str) -> Result<Self, tonic::transport::Error> {
        Self::connect_lazy(tonic::transport::Endpoint::from_static(uri))
    }

    /// Connects to an endpoint. Does not connect until we try to send a request.
    ///
    /// Note: You must have entered the tokio runtime context before calling this function.
    /// You can do so by writing the code down below, or it will automatically be entered, if
    /// you have an `.await` before calling this. Consider using the `async` functions instead.
    ///
    /// ```rust,ignore
    /// let handle = tokio::runtime::Handle::current();
    /// handle.enter();
    /// ```
    pub fn connect_lazy(
        endpoint: tonic::transport::Endpoint,
    ) -> Result<Self, tonic::transport::Error> {
        Ok(Self {
            inner: Grpc::new(endpoint.connect_lazy()),
        })
    }

    /// Builds a lazy connection to the Mainnet access node provided by Dapper Labs.
    ///
    /// Note: You must have entered the tokio runtime context before calling this function.
    /// You can do so by writing the code down below, or it will automatically be entered, if
    /// you have an `.await` before calling this. Consider using the `async` functions instead.
    ///
    /// ```rust,ignore
    /// let handle = tokio::runtime::Handle::current();
    /// handle.enter();
    /// ```
    pub fn mainnet_lazy() -> Result<Self, tonic::transport::Error> {
        Self::connect_static_lazy("http://access.mainnet.nodes.onflow.org:9000")
    }

    /// Builds a lazy connection to the Testnet access node provided by Dapper Labs.
    ///
    /// Note: You must have entered the tokio runtime context before calling this function.
    /// You can do so by writing the code down below, or it will automatically be entered, if
    /// you have an `.await` before calling this. Consider using the `async` functions instead.
    ///
    /// ```rust,ignore
    /// let handle = tokio::runtime::Handle::current();
    /// handle.enter();
    /// ```
    pub fn testnet_lazy() -> Result<Self, tonic::transport::Error> {
        Self::connect_static_lazy("http://access.devnet.nodes.onflow.org:9000")
    }
}

impl<I, O, Service> GrpcClient<I, O> for Grpc<Service>
where
    I: FlowRequest<O> + Send + Sync + EncodableMessage,
    O: for<'b> DecodableMessage<'b> + Send + Sync + Default + 'static,
    Service: GrpcService<BoxBody> + 'static,
    Service::Error: Into<Box<dyn Error + Send + Sync>>,
    Service::ResponseBody: Body + Send + Sync + 'static,
    <Service::ResponseBody as Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Error = TonicError;

    fn send(&mut self, input: I) -> GrpcSendResult<O> {
        let preenc = PreEncode::new(&input);
        Box::pin(async move {
            self.ready().await.map_err(Into::into)?;
            Ok(self
                .unary(
                    Request::new(preenc),
                    PathAndQuery::from_static(I::PATH),
                    OtoprCodec::default(),
                )
                .await?
                .into_inner())
        })
    }
}

impl<Inner, I, O> GrpcClient<I, O> for FlowClient<Inner>
where
    Inner: GrpcClient<I, O>,
{
    type Error = Inner::Error;

    #[inline]
    fn send<'a>(
        &'a mut self,
        input: I,
    ) -> Pin<Box<dyn Future<Output = Result<O, Self::Error>> + 'a>> {
        self.inner.send(input)
    }
}
