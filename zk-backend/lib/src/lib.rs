use alloy_sol_types::sol;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        address signer_address;
        address receipent_address;
        string first_name;
        string last_name;
        uint64 date_of_birth;
        uint64 adhaar_number;
    }
}


