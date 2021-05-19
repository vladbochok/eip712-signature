use crate::{
    struct_builder::StructBuilder,
    typed_structure::{EIP712TypedStructure, Eip712Domain},
    PackedEthSignature,
};
use parity_crypto::Keccak256;
use std::str::FromStr;
use web3::types::{Address, H256, U256};

#[derive(Clone)]
struct Person {
    name: String,
    wallet: Address,
}

impl EIP712TypedStructure for Person {
    const TYPE_NAME: &'static str = "Person";

    fn build_structure<BUILDER: StructBuilder>(&self, builder: &mut BUILDER) {
        builder.add_member("name", &self.name);
        builder.add_member("wallet", &self.wallet);
    }
}

#[derive(Clone)]
struct Mail {
    from: Person,
    to: Person,
    contents: String,
}

impl EIP712TypedStructure for Mail {
    const TYPE_NAME: &'static str = "Mail";
    fn build_structure<BUILDER: StructBuilder>(&self, builder: &mut BUILDER) {
        builder.add_member("from", &self.from);
        builder.add_member("to", &self.to);
        builder.add_member("contents", &self.contents);
    }
}

#[test]
fn test_encode_eip712_typed_struct() {
    let domain = Eip712Domain {
        name: "Ether Mail".to_owned(),
        version: "1".to_owned(),
        chain_id: U256::from(1),
        verifying_contract: Address::from_str("CcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC").unwrap(),
    };

    let message = Mail {
        from: Person {
            name: "Cow".to_owned(),
            wallet: Address::from_str("CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826").unwrap(),
        },
        to: Person {
            name: "Bob".to_owned(),
            wallet: Address::from_str("bBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB").unwrap(),
        },
        contents: "Hello, Bob!".to_string(),
    };

    assert_eq!(
        &message.encode_type(),
        "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
    );

    assert_eq!(
        &message.encode_data()[..],
        [
            H256::from_str("fc71e5fa27ff56c350aa531bc129ebdf613b772b6604664f5d8dbe21b85eb0c8")
                .unwrap(),
            H256::from_str("cd54f074a4af31b4411ff6a60c9719dbd559c221c8ac3492d9d872b041d703d1")
                .unwrap(),
            H256::from_str("b5aadf3154a261abdd9086fc627b61efca26ae5702701d05cd2305f7c52a2fc8")
                .unwrap()
        ]
    );

    assert_eq!(
        message.hash_struct(),
        H256::from_str("c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e").unwrap()
    );

    assert_eq!(
        &domain.encode_type(),
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    assert_eq!(
        &domain.encode_data()[..],
        [
            H256::from_str("c70ef06638535b4881fafcac8287e210e3769ff1a8e91f1b95d6246e61e4d3c6")
                .unwrap(),
            H256::from_str("c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6")
                .unwrap(),
            H256::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
            H256::from_str("000000000000000000000000CcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
                .unwrap(),
        ]
    );

    assert_eq!(
        domain.hash_struct(),
        H256::from_str("f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f").unwrap()
    );

    let private_key = b"cow".keccak256().into();
    let address_owner = PackedEthSignature::address_from_private_key(&private_key).unwrap();

    let signature = PackedEthSignature::sign_typed_data(&private_key, &domain, &message).unwrap();
    let signed_bytes = PackedEthSignature::typed_data_to_signed_bytes(&domain, &message);

    assert_eq!(
        address_owner,
        signature.signature_recover_signer(&signed_bytes).unwrap()
    );
}
