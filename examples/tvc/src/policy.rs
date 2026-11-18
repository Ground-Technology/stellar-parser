use stellar_parser::{parse_base64, xdr};

fn authorization_allowed(
    invocation: &xdr::SorobanAuthorizedInvocation,
    allowed_contract: &xdr::ScAddress,
) -> bool {
    let xdr::SorobanAuthorizedFunction::ContractFn(call) = &invocation.function else {
        return false;
    };
    call.contract_address == *allowed_contract
        && invocation
            .sub_invocations
            .iter()
            .all(|child| authorization_allowed(child, allowed_contract))
}

pub fn evaluate(
    envelope_xdr: &str,
    network: &str,
    requested_digest: &[u8; 32],
    allowed_contract: &xdr::ContractId,
) -> Result<bool, stellar_parser::Error> {
    let parsed = parse_base64(envelope_xdr, network)?;
    parsed.verify_signing_hash(requested_digest)?;
    let operations = &parsed.transaction().operations;
    let allowed_contract = xdr::ScAddress::Contract(allowed_contract.clone());
    Ok(!operations.is_empty()
        && operations.iter().all(|operation| {
            let xdr::OperationBody::InvokeHostFunction(host) = &operation.body else {
                return false;
            };
            let xdr::HostFunction::InvokeContract(call) = &host.host_function else {
                return false;
            };
            call.contract_address == allowed_contract
                && host
                    .auth
                    .iter()
                    .all(|entry| authorization_allowed(&entry.root_invocation, &allowed_contract))
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    fn digest_from_hex(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
        hex::decode(value)?
            .try_into()
            .map_err(|_| "invalid digest length".into())
    }
    use stellar_parser::xdr::{ReadXdr, WriteXdr};

    const NETWORK: &str = "Test SDF Network ; September 2015";
    const FIXTURE: &str = include_str!("../fixtures/contract_call.xdr");

    fn allowed_contract() -> xdr::ContractId {
        xdr::ContractId(xdr::Hash([5; 32]))
    }

    fn fixture() -> Result<xdr::TransactionV1Envelope, Box<dyn Error>> {
        let envelope = xdr::TransactionEnvelope::from_xdr_base64(FIXTURE, xdr::Limits::none())?;
        let xdr::TransactionEnvelope::Tx(envelope) = envelope else {
            return Err("expected a v1 envelope".into());
        };
        Ok(envelope)
    }

    fn entry_mut<T, const MAX: u32>(
        entries: &mut xdr::VecM<T, MAX>,
        index: usize,
    ) -> Result<&mut T, Box<dyn Error>> {
        entries
            .iter_mut()
            .nth(index)
            .ok_or_else(|| "missing fixture entry".into())
    }

    fn host(
        operation: &mut xdr::Operation,
    ) -> Result<&mut xdr::InvokeHostFunctionOp, Box<dyn Error>> {
        let xdr::OperationBody::InvokeHostFunction(host) = &mut operation.body else {
            return Err("expected a host function".into());
        };
        Ok(host)
    }

    fn check(envelope: xdr::TransactionV1Envelope) -> Result<bool, Box<dyn Error>> {
        let encoded = xdr::TransactionEnvelope::Tx(envelope).to_xdr_base64(xdr::Limits::none())?;
        let parsed = parse_base64(&encoded, NETWORK)?;
        Ok(evaluate(
            &encoded,
            NETWORK,
            parsed.signing_hash(),
            &allowed_contract(),
        )?)
    }

    #[test]
    fn accepts_the_fixture_with_an_independently_computed_digest() -> Result<(), Box<dyn Error>> {
        let digest = digest_from_hex(include_str!("../fixtures/contract_call.sha256").trim())?;
        let configured: xdr::ContractId =
            "CACQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQLC2U".parse()?;
        assert_eq!(configured, allowed_contract());
        assert!(evaluate(FIXTURE, NETWORK, &digest, &configured)?);
        Ok(())
    }

    #[test]
    fn allows_any_function_arguments_and_multiple_calls_to_the_allowed_contract()
    -> Result<(), Box<dyn Error>> {
        let mut envelope = fixture()?;
        let host = host(entry_mut(&mut envelope.tx.operations, 0)?)?;
        let xdr::HostFunction::InvokeContract(call) = &mut host.host_function else {
            return Err("expected a contract call".into());
        };
        call.function_name = xdr::ScSymbol(b"another_function".to_vec().try_into()?);
        call.args = vec![
            xdr::ScVal::I64(-7),
            xdr::ScVal::Address(xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash(
                [9; 32],
            )))),
        ]
        .try_into()?;
        host.auth = xdr::VecM::default();
        assert!(check(envelope.clone())?);
        envelope.tx.operations = vec![
            fixture()?.tx.operations[0].clone(),
            envelope.tx.operations[0].clone(),
        ]
        .try_into()?;
        assert!(check(envelope)?);
        Ok(())
    }

    #[test]
    fn rejects_other_contracts_even_when_an_allowed_call_is_present() -> Result<(), Box<dyn Error>>
    {
        let mut forbidden = fixture()?.tx.operations[0].clone();
        let xdr::HostFunction::InvokeContract(call) = &mut host(&mut forbidden)?.host_function
        else {
            return Err("expected a contract call".into());
        };
        call.contract_address = xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash([9; 32])));
        let allowed = fixture()?.tx.operations[0].clone();
        for operations in [
            vec![forbidden.clone()],
            vec![allowed.clone(), forbidden.clone()],
            vec![forbidden, allowed],
        ] {
            let mut envelope = fixture()?;
            envelope.tx.operations = operations.try_into()?;
            assert!(!check(envelope)?);
        }
        Ok(())
    }

    #[test]
    fn rejects_empty_transactions_classic_operations_and_other_host_functions()
    -> Result<(), Box<dyn Error>> {
        let mut envelope = fixture()?;
        envelope.tx.operations = xdr::VecM::default();
        assert!(!check(envelope)?);
        let classic = xdr::Operation {
            source_account: None,
            body: xdr::OperationBody::ChangeTrust(xdr::ChangeTrustOp::default()),
        };
        let mut forbidden = vec![classic];
        for function in [
            xdr::HostFunction::UploadContractWasm(vec![1, 2, 3].try_into()?),
            xdr::HostFunction::CreateContract(xdr::CreateContractArgs::default()),
            xdr::HostFunction::CreateContractV2(xdr::CreateContractArgsV2::default()),
        ] {
            let mut operation = fixture()?.tx.operations[0].clone();
            host(&mut operation)?.host_function = function;
            forbidden.push(operation);
        }
        for operation in forbidden {
            for operations in [
                vec![operation.clone()],
                vec![fixture()?.tx.operations[0].clone(), operation],
            ] {
                let mut envelope = fixture()?;
                envelope.tx.operations = operations.try_into()?;
                assert!(!check(envelope)?);
            }
        }
        Ok(())
    }

    #[test]
    fn checks_every_authorization_root_and_nested_invocation() -> Result<(), Box<dyn Error>> {
        for nested in [false, true] {
            let mut envelope = fixture()?;
            let auth = &mut host(entry_mut(&mut envelope.tx.operations, 0)?)?.auth;
            let mut forbidden = auth[0].clone();
            let invocation = if nested {
                let child = forbidden.root_invocation.sub_invocations[0].clone();
                forbidden.root_invocation.sub_invocations =
                    vec![child.clone(), child].try_into()?;
                entry_mut(&mut forbidden.root_invocation.sub_invocations, 1)?
            } else {
                &mut forbidden.root_invocation
            };
            let xdr::SorobanAuthorizedFunction::ContractFn(call) = &mut invocation.function else {
                return Err("expected an authorized contract call".into());
            };
            call.contract_address = xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash([9; 32])));
            *auth = vec![auth[0].clone(), forbidden].try_into()?;
            assert!(!check(envelope)?);
        }
        Ok(())
    }

    #[test]
    fn rejects_contract_creation_anywhere_in_authorization_trees() -> Result<(), Box<dyn Error>> {
        for function in [
            xdr::SorobanAuthorizedFunction::CreateContractHostFn(xdr::CreateContractArgs::default()),
            xdr::SorobanAuthorizedFunction::CreateContractV2HostFn(
                xdr::CreateContractArgsV2::default(),
            ),
        ] {
            for nested in [false, true] {
                let mut envelope = fixture()?;
                let root = &mut entry_mut(
                    &mut host(entry_mut(&mut envelope.tx.operations, 0)?)?.auth,
                    0,
                )?
                .root_invocation;
                let invocation = if nested {
                    entry_mut(&mut root.sub_invocations, 0)?
                } else {
                    root
                };
                invocation.function = function.clone();
                assert!(!check(envelope)?);
            }
        }
        Ok(())
    }

    #[test]
    fn checks_authorizations_beyond_the_first_nested_level() -> Result<(), Box<dyn Error>> {
        let mut envelope = fixture()?;
        let root = &mut entry_mut(
            &mut host(entry_mut(&mut envelope.tx.operations, 0)?)?.auth,
            0,
        )?
        .root_invocation;
        let child = root.sub_invocations[0].clone();
        entry_mut(&mut root.sub_invocations, 0)?.sub_invocations = vec![child].try_into()?;
        assert!(check(envelope.clone())?);
        let root = &mut entry_mut(
            &mut host(entry_mut(&mut envelope.tx.operations, 0)?)?.auth,
            0,
        )?
        .root_invocation;
        let child = entry_mut(&mut root.sub_invocations, 0)?;
        let descendant = entry_mut(&mut child.sub_invocations, 0)?;
        let xdr::SorobanAuthorizedFunction::ContractFn(call) = &mut descendant.function else {
            return Err("expected an authorized contract call".into());
        };
        call.contract_address = xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash([9; 32])));
        assert!(!check(envelope)?);
        Ok(())
    }

    #[test]
    fn returns_errors_for_malformed_input_wrong_network_and_digest_mismatches()
    -> Result<(), Box<dyn Error>> {
        let digest = digest_from_hex(include_str!("../fixtures/contract_call.sha256").trim())?;
        assert!(matches!(
            evaluate(FIXTURE, NETWORK, &[0; 32], &allowed_contract()),
            Err(stellar_parser::Error::SigningHashMismatch)
        ));
        assert!(matches!(
            evaluate(
                FIXTURE,
                "Public Global Stellar Network ; September 2015",
                &digest,
                &allowed_contract()
            ),
            Err(stellar_parser::Error::SigningHashMismatch)
        ));
        assert!(matches!(
            evaluate("not XDR", NETWORK, &digest, &allowed_contract()),
            Err(stellar_parser::Error::InvalidXdr(_))
        ));
        Ok(())
    }
}
