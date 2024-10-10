use crate::byte_utils::field_to_bytes;
use ark_bn254::Fr;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};

#[derive(Clone)]
pub struct ExampleCircuit {
    pub some_value: Option<Fr>,
}

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

    pub fn public_inputs(&self) -> Vec<[u8; 32]> {
        let public_inputs: Vec<[u8; 32]> = vec![field_to_bytes(self.some_value.unwrap())];

        public_inputs
    }
}

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
