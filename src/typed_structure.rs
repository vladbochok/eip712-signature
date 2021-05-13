use parity_crypto::Keccak256;
use web3::types::{Address, H256, U256};

use crate::struct_builder::{EncodeBuilder, StructBuilder, TypeBuilder};

#[derive(Debug, Clone)]
pub struct EncodedStructureMember {
    /// Type identifier.
    pub member_type: String,
    /// Name identifier.
    pub name: String,
    /// Flag denoting structure or elementary type.
    pub is_reference_type: bool,
    // Members that are inside this member.
    pub inner_members: Vec<EncodedStructureMember>,
}

impl EncodedStructureMember {
    pub fn encode<MEMBER: StructMember>(name: &str, member: &MEMBER) -> Self {
        Self {
            member_type: member.member_type(),
            name: name.to_string(),
            is_reference_type: member.is_reference_type(),
            inner_members: member.get_inner_members(),
        }
    }

    /// Encodes the structure as `name ‖ "(" ‖ member₁ ‖ "," ‖ member₂ ‖ "," ‖ … ‖ memberₙ ")".
    pub fn get_encoded_type(&self) -> String {
        let mut encoded_type = String::new();
        encoded_type.push_str(&self.member_type);
        encoded_type.push('(');

        let mut members = self.inner_members.iter();

        if let Some(member) = members.next() {
            encoded_type.push_str(&member.member_type);
            encoded_type.push(' ');
            encoded_type.push_str(&member.name);
        }
        for member in members {
            encoded_type.push(',');
            encoded_type.push_str(&member.member_type);
            encoded_type.push(' ');
            encoded_type.push_str(&member.name);
        }

        encoded_type.push(')');

        encoded_type
    }
}

pub trait StructMember {
    const MEMBER_TYPE: &'static str;
    const IS_REFERENCE_TYPE: bool;

    fn member_type(&self) -> String {
        Self::MEMBER_TYPE.to_string()
    }

    fn is_reference_type(&self) -> bool {
        Self::IS_REFERENCE_TYPE
    }

    fn get_inner_members(&self) -> Vec<EncodedStructureMember>;

    fn encode_member_data(&self) -> H256;
}

impl<TypedStructure: EIP712TypedStructure> StructMember for TypedStructure {
    const MEMBER_TYPE: &'static str = Self::TYPE_NAME;
    const IS_REFERENCE_TYPE: bool = true;

    fn get_inner_members(&self) -> Vec<EncodedStructureMember> {
        let mut builder = TypeBuilder::new();
        self.build_structure(&mut builder);

        builder.get_inner_members()
    }

    fn encode_member_data(&self) -> H256 {
        self.hash_struct()
    }
}

/// Interface for defining the structure for the EIP712 signature.
pub trait EIP712TypedStructure {
    const TYPE_NAME: &'static str;

    fn build_structure<BUILDER: StructBuilder>(&self, builder: &mut BUILDER);

    fn encode_type(&self) -> String {
        let mut builder = EncodeBuilder::new();
        self.build_structure(&mut builder);

        builder.encode_type(&Self::TYPE_NAME)
    }

    fn encode_data(&self) -> Vec<H256> {
        let mut builder = EncodeBuilder::new();
        self.build_structure(&mut builder);

        builder.encode_data()
    }

    fn type_hash(&self) -> H256 {
        let encode_type = self.encode_type();
        encode_type.keccak256().into()
    }

    fn hash_struct(&self) -> H256 {
        // hashStruct(s : 𝕊) = keccak256(keccak256(encodeType(typeOf(s))) ‖ encodeData(s)).
        let type_hash = self.type_hash();
        let encode_data = self.encode_data();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&type_hash.as_bytes());
        for data in encode_data {
            bytes.extend_from_slice(&data.as_bytes());
        }

        bytes.keccak256().into()
    }
}

#[derive(Debug, Clone)]
pub struct Eip712Domain {
    /// The user readable name of signing domain, i.e. the name of the DApp or the protocol.
    pub name: String,
    /// The current major version of the signing domain. Signatures from different versions are not compatible.
    pub version: String,
    /// The [EIP-155](https://eips.ethereum.org/EIPS/eip-155) chain id.
    pub chain_id: U256,
    /// the address of the contract that will verify the signature.
    pub verifying_contract: Address,
}

impl Eip712Domain {
    pub fn new(name: String, version: String, verifying_contract: Address, chain_id: U256) -> Self {
        Self {
            name,
            version,
            verifying_contract,
            chain_id: chain_id,
        }
    }
}

impl EIP712TypedStructure for Eip712Domain {
    const TYPE_NAME: &'static str = "EIP712Domain";

    fn build_structure<BUILDER: StructBuilder>(&self, builder: &mut BUILDER) {
        builder.add_member("name", &self.name);
        builder.add_member("version", &self.version);
        builder.add_member("chainId", &self.chain_id);
        builder.add_member("verifyingContract", &self.verifying_contract);
    }
}
