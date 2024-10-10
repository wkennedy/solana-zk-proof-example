use crate::byte_utils::field_to_bytes;
use ark_bn254::Fr;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};

#[derive(Clone)]
pub struct ExampleCircuit {
    pub some_value: Option<Fr>,
}

/// This implementation defines the Default and New methods for the ExampleCircuit struct,
/// providing ways to initialize the struct with default and specific values. Additionally,
/// it includes a method to retrieve the public inputs of the circuit and a method to generate
/// constraints for the ExampleCircuit as part of the ConstraintSynthesizer trait implementation.
impl ExampleCircuit {
    pub fn default() -> Self {
        ExampleCircuit { some_value: None }
    }

    pub fn new() -> Self {
        let circuit = ExampleCircuit {
            some_value: Some(Fr::from(100)),
        };

        circuit
    }

    /// This is a convenience function that returns a vector of public inputs for the circuit.
    ///
    /// This function converts the value stored in `some_value` to a 32-byte array
    /// using the `field_to_bytes` function. If `some_value` is not set (i.e., is `None`),
    /// the function will panic.
    ///
    /// # Returns
    ///
    /// A vector containing a single element: the 32-byte array representation of the
    /// value stored in `some_value`.
    ///
    /// # Panics
    ///
    /// This function will panic if `some_value` is `None`.
    pub fn public_inputs(&self) -> Vec<[u8; 32]> {
        let public_inputs: Vec<[u8; 32]> = vec![field_to_bytes(self.some_value.unwrap())];

        public_inputs
    }
}

/// This `ExampleCircuit` struct represents a simple example of a constraint system circuit
/// that can be used with zkSNARKs. The circuit defines a single field element as its
/// internal state and includes methods to initialize the circuit, retrieve its public inputs,
/// and generate the constraints required for the zkSNARK proof system.
///
/// The struct utilizes the `Fr` field element from the `ark_bn254` crate and implements the
/// `ConstraintSynthesizer` trait from the `ark_relations` crate to define the circuit's
/// constraints.

/// # Fields
///
/// - `some_value`: An optional field element representing the internal state of the circuit. The
/// field is of type `Option<Fr>` where `Fr` is a field element from the `ark_bn254` crate.
///
/// # Methods
///
/// - `default()`: Creates a new `ExampleCircuit` instance with its `some_value` set to `None`.
///
/// - `new()`: Creates a new `ExampleCircuit` instance with its `some_value` set to a specific
/// value (`Fr::from(100)`).
///
/// - `public_inputs()`: Returns a vector containing the 32-byte array representation of the value
/// stored in `some_value`. This function will panic if `some_value` is `None`.
///
/// # Traits
///
/// - `ConstraintSynthesizer<Fr>`:
///   - `generate_constraints()`: Generates the constraints for the circuit, ensuring that the
///   public input (`some_value`) is correctly constrained and matches the computed value.
impl ConstraintSynthesizer<Fr> for ExampleCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let some_value_var =
            cs.new_input_variable(|| self.some_value.ok_or(SynthesisError::AssignmentMissing))?;

        // Constraint: Ensure computed addresses_hash matches the provided addresses_hash
        cs.enforce_constraint(
            lc!() + some_value_var,
            lc!() + Variable::One,
            lc!() + some_value_var,
        )?;

        Ok(())
    }
}
