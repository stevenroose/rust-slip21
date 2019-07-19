
# rust-slip21


## Example

```rust
let seed = hex::decode("c76c4ac4f4e4a00d6b274d5c39c700bb4a7ddc04fbc6f78e85ca75007b5b495f74a9043eeb77bdd53aa6fc3a0e31462270316fa04b8c19114c8798706cd02ac8").unwrap();

let master = Node::new_master(&seed);
assert_eq!(master.key(), &hex::decode("dbf12b44133eaab506a740f6565cc117228cbf1dd70635cfa8ddfdc9af734756").unwrap()[..]);

let child1 = master.derive_child("SLIP-0021".as_bytes());
assert_eq!(child1.key(), &hex::decode("1d065e3ac1bbe5c7fad32cf2305f7d709dc070d672044a19e610c77cdf33de0d").unwrap()[..]);

let child2 = child1.derive_child("Master encryption key".as_bytes());
assert_eq!(child2.key(), &hex::decode("ea163130e35bbafdf5ddee97a17b39cef2be4b4f390180d65b54cf05c6a82fde").unwrap()[..]);
```


# Licensing

The code in this project is licensed under the Creative Commons CC0 1.0
Universal license.
