extern crate bitcoin_hashes;
#[cfg(test)]
extern crate hex;
#[cfg(feature = "serde")]
extern crate serde;

use std::{cmp, fmt, hash};

use bitcoin_hashes::{hmac, sha512, Hash, HashEngine};

type Hmac = hmac::Hmac<sha512::Hash>;
type HmacEngine = hmac::HmacEngine<sha512::Hash>;

const HMAC_MASTER_NODE_KEY: &'static str = "Symmetric key seed";

/// A SLIP-21 derivation node.
pub struct Node([u8; 64]);

impl Copy for Node {}

impl Clone for Node {
	fn clone(&self) -> Node {
		let mut ret = [0; 64];
		ret.copy_from_slice(&self.0);
		Node(ret)
	}
}

impl PartialEq for Node {
	fn eq(&self, other: &Node) -> bool {
		self.0[..] == other.0[..]
	}
}

impl Eq for Node {}

impl Default for Node {
	fn default() -> Node {
		Node([0; 64])
	}
}

impl PartialOrd for Node {
	fn partial_cmp(&self, other: &Node) -> Option<cmp::Ordering> {
		(&self.0).partial_cmp(&other.0)
	}
}

impl Ord for Node {
	fn cmp(&self, other: &Node) -> cmp::Ordering {
		(&self.0).cmp(&other.0)
	}
}

impl hash::Hash for Node {
	fn hash<H: hash::Hasher>(&self, state: &mut H) {
		(&self.0).hash(state)
	}
}

impl ::std::str::FromStr for Node {
	type Err = ::bitcoin_hashes::Error;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		::bitcoin_hashes::hex::FromHex::from_hex(s)
	}
}

impl ::bitcoin_hashes::hex::FromHex for Node {
	fn from_byte_iter<I>(iter: I) -> Result<Self, ::bitcoin_hashes::Error>
		where I: Iterator<Item=Result<u8, ::bitcoin_hashes::Error>> +
			ExactSizeIterator +
			DoubleEndedIterator,
	{
		Ok(Node(::bitcoin_hashes::hex::FromHex::from_byte_iter(iter)?))
	}
}

impl ::std::fmt::LowerHex for Node {
	fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
		::bitcoin_hashes::hex::format_hex(&self.0, f)
	}
}

impl ::std::fmt::Debug for Node {
	fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
		::bitcoin_hashes::hex::format_hex(&self.0, f)
	}
}

impl ::std::fmt::Display for Node {
	fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
		::bitcoin_hashes::hex::format_hex(&self.0, f)
	}
}

impl ::std::ops::Index<usize> for Node {
	type Output = u8;
	fn index(&self, index: usize) -> &u8 {
		&self.0[index]
	}
}

impl ::std::ops::Index<::std::ops::Range<usize>> for Node {
	type Output = [u8];
	fn index(&self, index: ::std::ops::Range<usize>) -> &[u8] {
		&self.0[index]
	}
}

impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for Node {
	type Output = [u8];
	fn index(&self, index: ::std::ops::RangeFrom<usize>) -> &[u8] {
		&self.0[index]
	}
}

impl ::std::ops::Index<::std::ops::RangeTo<usize>> for Node {
	type Output = [u8];
	fn index(&self, index: ::std::ops::RangeTo<usize>) -> &[u8] {
		&self.0[index]
	}
}

impl ::std::ops::Index<::std::ops::RangeFull> for Node {
	type Output = [u8];
	fn index(&self, index: ::std::ops::RangeFull) -> &[u8] {
		&self.0[index]
	}
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for Node {
	fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		use ::bitcoin_hashes::hex::ToHex;
		if s.is_human_readable() {
			s.serialize_str(&self.to_hex())
		} else {
			s.serialize_bytes(&self[..])
		}
	}
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for Node {
	fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Node, D::Error> {
		use ::bitcoin_hashes::hex::FromHex;

		if d.is_human_readable() {
			struct HexVisitor;

			impl<'de> ::serde::de::Visitor<'de> for HexVisitor {
				type Value = Node;

				fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
					formatter.write_str("an ASCII hex string")
				}

				fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
				where
					E: ::serde::de::Error,
				{
					if let Ok(hex) = ::std::str::from_utf8(v) {
						Node::from_hex(hex).map_err(E::custom)
					} else {
						return Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self));
					}
				}

				fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
				where
					E: ::serde::de::Error,
				{
					Node::from_hex(v).map_err(E::custom)
				}
			}

			d.deserialize_str(HexVisitor)
		} else {
			struct BytesVisitor;

			impl<'de> ::serde::de::Visitor<'de> for BytesVisitor {
				type Value = Node;

				fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
					formatter.write_str("a bytestring")
				}

				fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
				where
					E: ::serde::de::Error,
				{
					if v.len() != 64 {
						Err(E::invalid_length(v.len(), &"64"))
					} else {
						let mut ret = [0; 64];
						ret.copy_from_slice(v);
						Ok(Node(ret))
					}
				}
			}

			d.deserialize_bytes(BytesVisitor)
		}
	}
}

impl Node {
	/// Create a new master node from a BIP-39 or SLIP-39 seed.
	///
	/// The seed is expected to be 64 bytes long.
	pub fn new_master(seed: &[u8]) -> Node {
		// m = HMAC-SHA512(key = b"Symmetric key seed", msg = S)
		let mut engine: HmacEngine = hmac::HmacEngine::new(HMAC_MASTER_NODE_KEY.as_bytes());
		engine.input(&seed);

		Node(Hmac::from_engine(engine).into_inner())
	}

	/// Derive the child node of this node.
	pub fn derive_child(&self, label: &[u8]) -> Node {
		// ChildNode(N, label) = HMAC-SHA512(key = N[0:32], msg = b"\x00" + label),
		let mut engine: HmacEngine = hmac::HmacEngine::new(&self.0[0..32]);
		engine.input(&[0]);
		engine.input(label);

		Node(Hmac::from_engine(engine).into_inner())
	}

	/// Get the symmetric key of a child node.
	pub fn key(&self) -> &[u8] {
		&self.0[32..]
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use hex;

	#[test]
	fn slip_example() {
		let seed = hex::decode("c76c4ac4f4e4a00d6b274d5c39c700bb4a7ddc04fbc6f78e85ca75007b5b495f74a9043eeb77bdd53aa6fc3a0e31462270316fa04b8c19114c8798706cd02ac8").unwrap();

		let master = Node::new_master(&seed);
		assert_eq!(master.key(), &hex::decode("dbf12b44133eaab506a740f6565cc117228cbf1dd70635cfa8ddfdc9af734756").unwrap()[..]);

		let child1 = master.derive_child("SLIP-0021".as_bytes());
		assert_eq!(child1.key(), &hex::decode("1d065e3ac1bbe5c7fad32cf2305f7d709dc070d672044a19e610c77cdf33de0d").unwrap()[..]);

		let child2 = child1.derive_child("Master encryption key".as_bytes());
		assert_eq!(child2.key(), &hex::decode("ea163130e35bbafdf5ddee97a17b39cef2be4b4f390180d65b54cf05c6a82fde").unwrap()[..]);
	}
}
