//! IR program executor.
//!
//! Executes an IR program against a target node over an established
//! `NoiseConnection`, producing side effects (sending/receiving messages).

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use smite::bolt::{
    AcceptChannel, ChannelId, Message, OpenChannel, OpenChannelTlvs, Pong, msg_type,
};
use smite::noise::NoiseConnection;
use smite_ir::operation::AcceptChannelField;
use smite_ir::{Operation, Program, Variable, VariableType};

/// Error from executing an IR program.
#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    /// Referenced a variable that doesn't exist (or a void instruction).
    #[error("variable index {index} out of bounds (have {len})")]
    VariableIndexOutOfBounds { index: usize, len: usize },

    /// Input variable has the wrong type.
    #[error("type mismatch: expected {expected:?}, got {got:?}")]
    TypeMismatch {
        expected: VariableType,
        got: VariableType,
    },

    /// Wrong number of inputs for the operation.
    #[error("wrong input count: expected {expected}, got {got}")]
    WrongInputCount { expected: usize, got: usize },

    /// Private key bytes are not in the valid range `[1, curve_order)`.
    #[error("invalid private key")]
    InvalidPrivateKey,

    /// Public key bytes are not a valid secp256k1 point.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// Connection or send/receive failure.
    #[error("connection: {0}")]
    Connection(#[from] smite::noise::ConnectionError),

    /// Failed to decode a received message.
    #[error("decode: {0}")]
    Decode(#[from] smite::bolt::BoltError),

    /// Received a different message type than expected.
    #[error("unexpected message: expected type {expected}, got {got}")]
    UnexpectedMessage { expected: u16, got: u16 },
}

/// Executes an IR program against a target over the given connection.
///
/// # Errors
///
/// Returns an error if any instruction fails (type mismatch, connection error,
/// decode error, etc.).
pub fn execute(program: &Program, conn: &mut NoiseConnection) -> Result<(), ExecuteError> {
    let secp = Secp256k1::new();
    let mut variables: Vec<Option<Variable>> = Vec::with_capacity(program.instructions.len());

    for instr in &program.instructions {
        // Validate input count before accessing inputs by index.
        let expected_count = instr.operation.input_types().len();
        if instr.inputs.len() != expected_count {
            return Err(ExecuteError::WrongInputCount {
                expected: expected_count,
                got: instr.inputs.len(),
            });
        }

        let result = match &instr.operation {
            // -- Load operations --
            Operation::LoadAmount(v) => Some(Variable::Amount(*v)),
            Operation::LoadFeeratePerKw(v) => Some(Variable::FeeratePerKw(*v)),
            Operation::LoadBlockHeight(v) => Some(Variable::BlockHeight(*v)),
            Operation::LoadU16(v) => Some(Variable::U16(*v)),
            Operation::LoadU8(v) => Some(Variable::U8(*v)),
            Operation::LoadBytes(b) => Some(Variable::Bytes(b.clone())),
            Operation::LoadFeatures(b) => Some(Variable::Features(b.clone())),
            Operation::LoadPrivateKey(k) => Some(Variable::PrivateKey(*k)),
            Operation::LoadChannelId(id) => Some(Variable::ChannelId(ChannelId::new(*id))),
            Operation::LoadTargetPubkeyFromContext => {
                let pk = PublicKey::from_slice(&program.context.target_pubkey)
                    .map_err(|_| ExecuteError::InvalidPublicKey)?;
                Some(Variable::Point(pk))
            }
            Operation::LoadChainHashFromContext => {
                Some(Variable::ChainHash(program.context.chain_hash))
            }

            // -- Compute operations --
            Operation::DerivePoint => {
                let key_bytes = resolve_private_key(&variables, instr.inputs[0])?;
                let sk = SecretKey::from_byte_array(*key_bytes)
                    .map_err(|_| ExecuteError::InvalidPrivateKey)?;
                let pk = PublicKey::from_secret_key(&secp, &sk);
                Some(Variable::Point(pk))
            }

            Operation::ExtractAcceptChannel(field) => {
                let ac = resolve_accept_channel(&variables, instr.inputs[0])?;
                Some(extract_field(ac, *field))
            }

            // -- Build operations --
            Operation::BuildOpenChannel => {
                let oc = build_open_channel(&variables, &instr.inputs)?;
                let encoded = Message::OpenChannel(oc).encode();
                Some(Variable::Message(encoded))
            }

            // -- Act operations --
            Operation::SendMessage => {
                let bytes = resolve_message(&variables, instr.inputs[0])?;
                conn.send_message(bytes)?;
                None
            }

            Operation::RecvAcceptChannel => {
                let ac = recv_accept_channel(conn)?;
                Some(Variable::AcceptChannel(ac))
            }
        };

        variables.push(result);
    }

    Ok(())
}

// -- Variable resolution --
//
// Each resolver looks up a variable by index and checks its type, returning the
// resolved variable.

fn resolve(variables: &[Option<Variable>], index: usize) -> Result<&Variable, ExecuteError> {
    variables
        .get(index)
        .and_then(Option::as_ref)
        .ok_or(ExecuteError::VariableIndexOutOfBounds {
            index,
            len: variables.len(),
        })
}

fn type_err(expected: VariableType, got: &Variable) -> ExecuteError {
    ExecuteError::TypeMismatch {
        expected,
        got: got.var_type(),
    }
}

fn resolve_amount(variables: &[Option<Variable>], index: usize) -> Result<u64, ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::Amount(v) => Ok(*v),
        _ => Err(type_err(VariableType::Amount, var)),
    }
}

fn resolve_feerate(variables: &[Option<Variable>], index: usize) -> Result<u32, ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::FeeratePerKw(v) => Ok(*v),
        _ => Err(type_err(VariableType::FeeratePerKw, var)),
    }
}

fn resolve_u16(variables: &[Option<Variable>], index: usize) -> Result<u16, ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::U16(v) => Ok(*v),
        _ => Err(type_err(VariableType::U16, var)),
    }
}

fn resolve_u8(variables: &[Option<Variable>], index: usize) -> Result<u8, ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::U8(v) => Ok(*v),
        _ => Err(type_err(VariableType::U8, var)),
    }
}

fn resolve_bytes(variables: &[Option<Variable>], index: usize) -> Result<&[u8], ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::Bytes(v) => Ok(v),
        _ => Err(type_err(VariableType::Bytes, var)),
    }
}

fn resolve_features(variables: &[Option<Variable>], index: usize) -> Result<&[u8], ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::Features(v) => Ok(v),
        _ => Err(type_err(VariableType::Features, var)),
    }
}

fn resolve_chain_hash(
    variables: &[Option<Variable>],
    index: usize,
) -> Result<[u8; 32], ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::ChainHash(v) => Ok(*v),
        _ => Err(type_err(VariableType::ChainHash, var)),
    }
}

fn resolve_channel_id(
    variables: &[Option<Variable>],
    index: usize,
) -> Result<ChannelId, ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::ChannelId(v) => Ok(*v),
        _ => Err(type_err(VariableType::ChannelId, var)),
    }
}

fn resolve_pubkey(variables: &[Option<Variable>], index: usize) -> Result<PublicKey, ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::Point(pk) => Ok(*pk),
        _ => Err(type_err(VariableType::Point, var)),
    }
}

fn resolve_private_key(
    variables: &[Option<Variable>],
    index: usize,
) -> Result<&[u8; 32], ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::PrivateKey(v) => Ok(v),
        _ => Err(type_err(VariableType::PrivateKey, var)),
    }
}

fn resolve_message(variables: &[Option<Variable>], index: usize) -> Result<&[u8], ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::Message(v) => Ok(v),
        _ => Err(type_err(VariableType::Message, var)),
    }
}

fn resolve_accept_channel(
    variables: &[Option<Variable>],
    index: usize,
) -> Result<&AcceptChannel, ExecuteError> {
    let var = resolve(variables, index)?;
    match var {
        Variable::AcceptChannel(v) => Ok(v),
        _ => Err(type_err(VariableType::AcceptChannel, var)),
    }
}

// -- Operation handlers --

/// Builds an `OpenChannel` from 20 input variables (wire order).
fn build_open_channel(
    variables: &[Option<Variable>],
    inputs: &[usize],
) -> Result<OpenChannel, ExecuteError> {
    Ok(OpenChannel {
        chain_hash: resolve_chain_hash(variables, inputs[0])?,
        temporary_channel_id: resolve_channel_id(variables, inputs[1])?,
        funding_satoshis: resolve_amount(variables, inputs[2])?,
        push_msat: resolve_amount(variables, inputs[3])?,
        dust_limit_satoshis: resolve_amount(variables, inputs[4])?,
        max_htlc_value_in_flight_msat: resolve_amount(variables, inputs[5])?,
        channel_reserve_satoshis: resolve_amount(variables, inputs[6])?,
        htlc_minimum_msat: resolve_amount(variables, inputs[7])?,
        feerate_per_kw: resolve_feerate(variables, inputs[8])?,
        to_self_delay: resolve_u16(variables, inputs[9])?,
        max_accepted_htlcs: resolve_u16(variables, inputs[10])?,
        funding_pubkey: resolve_pubkey(variables, inputs[11])?,
        revocation_basepoint: resolve_pubkey(variables, inputs[12])?,
        payment_basepoint: resolve_pubkey(variables, inputs[13])?,
        delayed_payment_basepoint: resolve_pubkey(variables, inputs[14])?,
        htlc_basepoint: resolve_pubkey(variables, inputs[15])?,
        first_per_commitment_point: resolve_pubkey(variables, inputs[16])?,
        channel_flags: resolve_u8(variables, inputs[17])?,
        tlvs: OpenChannelTlvs {
            upfront_shutdown_script: nonempty_or_none(resolve_bytes(variables, inputs[18])?),
            channel_type: nonempty_or_none(resolve_features(variables, inputs[19])?),
        },
    })
}

/// Receives the next non-ping message, automatically responding to pings.
fn recv_non_ping(conn: &mut NoiseConnection) -> Result<Message, ExecuteError> {
    loop {
        let msg_bytes = conn.recv_message()?;
        let msg = Message::decode(&msg_bytes)?;
        if let Message::Ping(ping) = msg {
            let pong = Message::Pong(Pong::respond_to(&ping)).encode();
            conn.send_message(&pong)?;
            continue;
        }
        return Ok(msg);
    }
}

/// Receives and decodes an `accept_channel` message.
fn recv_accept_channel(conn: &mut NoiseConnection) -> Result<AcceptChannel, ExecuteError> {
    match recv_non_ping(conn)? {
        Message::AcceptChannel(ac) => Ok(ac),
        other => Err(ExecuteError::UnexpectedMessage {
            expected: msg_type::ACCEPT_CHANNEL,
            got: other.msg_type(),
        }),
    }
}

/// Extracts a field from a parsed `accept_channel` message.
fn extract_field(ac: &AcceptChannel, field: AcceptChannelField) -> Variable {
    match field {
        AcceptChannelField::TemporaryChannelId => Variable::ChannelId(ac.temporary_channel_id),
        AcceptChannelField::DustLimitSatoshis => Variable::Amount(ac.dust_limit_satoshis),
        AcceptChannelField::MaxHtlcValueInFlightMsat => {
            Variable::Amount(ac.max_htlc_value_in_flight_msat)
        }
        AcceptChannelField::ChannelReserveSatoshis => Variable::Amount(ac.channel_reserve_satoshis),
        AcceptChannelField::HtlcMinimumMsat => Variable::Amount(ac.htlc_minimum_msat),
        AcceptChannelField::MinimumDepth => Variable::BlockHeight(ac.minimum_depth),
        AcceptChannelField::ToSelfDelay => Variable::U16(ac.to_self_delay),
        AcceptChannelField::MaxAcceptedHtlcs => Variable::U16(ac.max_accepted_htlcs),
        AcceptChannelField::FundingPubkey => Variable::Point(ac.funding_pubkey),
        AcceptChannelField::RevocationBasepoint => Variable::Point(ac.revocation_basepoint),
        AcceptChannelField::PaymentBasepoint => Variable::Point(ac.payment_basepoint),
        AcceptChannelField::DelayedPaymentBasepoint => {
            Variable::Point(ac.delayed_payment_basepoint)
        }
        AcceptChannelField::HtlcBasepoint => Variable::Point(ac.htlc_basepoint),
        AcceptChannelField::FirstPerCommitmentPoint => {
            Variable::Point(ac.first_per_commitment_point)
        }
        AcceptChannelField::UpfrontShutdownScript => {
            Variable::Bytes(ac.tlvs.upfront_shutdown_script.clone().unwrap_or_default())
        }
        AcceptChannelField::ChannelType => {
            Variable::Features(ac.tlvs.channel_type.clone().unwrap_or_default())
        }
    }
}

/// Returns `None` for empty slices, `Some(vec)` otherwise.
fn nonempty_or_none(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        None
    } else {
        Some(bytes.to_vec())
    }
}
