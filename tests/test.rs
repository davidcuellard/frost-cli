// Test module for frost_cli
#[cfg(test)]
mod tests {
    use frost_cli::{generate_keys, sign_message, validate_signature};
    use std::fs::{self, remove_file};

    #[test]
    fn test_generate_keys() {
        let keys_file = "./results/test_generate_keys_frost_keys.json";
        let result = generate_keys(3, 5, keys_file);
        assert!(result.is_ok(), "Failed to generate keys with t=3, n=5: {:?}", result.err());
        assert!(fs::metadata(keys_file).is_ok(), "Keys file not found: {}", keys_file);
        remove_file(keys_file).unwrap();
    }

    #[test]
    fn test_sign_message() {
        let keys_file = "./results/test_sign_message_frost_keys.json";
        let signature_file = "./results/test_sign_message_signature.json";
        let result = generate_keys(3, 5, keys_file);
        assert!(result.is_ok(), "Failed to generate keys with t=3, n=5: {:?}", result.err());
        let message = "hi, this is a test";
        let result = sign_message(message, 3, 5, &keys_file, &signature_file);
        assert!(result.is_ok(), "Failed to sign message with t=3, n=5: {:?}", result.err());
        assert!(fs::metadata(signature_file).is_ok(), "Signature file not found: {}", signature_file);
        remove_file(keys_file).unwrap();
        remove_file(signature_file).unwrap();
    }

    #[test]
    fn test_sign_message_greater_t() {
        let keys_file = "./results/test_sign_message_greater_t_frost_keys.json";
        let signature_file = "./results/test_sign_message_greater_t_signature.json";
        let result = generate_keys(3, 5, keys_file);
        assert!(result.is_ok(), "Failed to generate keys with t=3, n=5: {:?}", result.err());
        let message = "hi, this is a test";
        let result = sign_message(message, 4, 5, &keys_file, &signature_file);
        assert!(result.is_ok(), "Signing should succeed with t=4, n=5 when keys were generated with t=3, n=5");
        assert!(fs::metadata(signature_file).is_ok(), "Signature file not found: {}", signature_file);
        remove_file(keys_file).unwrap();
        remove_file(signature_file).unwrap();
    }

    #[test]
    fn test_verify_signature() {
        let keys_file = "./results/test_verify_signature_frost_keys.json";
        let signature_file = "./results/test_verify_signature_signature.json";
        let result = generate_keys(3, 5, keys_file);
        assert!(result.is_ok(), "Failed to generate keys with t=3, n=5: {:?}", result.err());
        let message = "hi, this is a test";
        let result = sign_message(message, 3, 5, &keys_file, &signature_file);
        assert!(result.is_ok(), "Failed to sign message with t=3, n=5: {:?}", result.err());
        let result = validate_signature(message, &keys_file, &signature_file);
        assert!(result.is_ok(), "Failed to verify signature for message: {}", message);
        remove_file(keys_file).unwrap();
        remove_file(signature_file).unwrap();
    }

    // fail tests
    #[test]
    fn test_sign_message_fail() {
        let keys_file = "./results/test_sign_message_fail_frost_keys.json";
        let signature_file = "./results/test_sign_message_fail_signature.json";
        let result = generate_keys(2, 5, keys_file);
        assert!(result.is_ok(), "Failed to generate keys with t=2, n=5: {:?}", result.err());
        let message = "hi, this is a test";
        let result = sign_message(message, 1, 5, &keys_file, &signature_file);
        assert!(result.is_err(), "Signing should fail with t=1, n=5 when keys were generated with t=2, n=5");
        remove_file(keys_file).unwrap();
    }

    #[test]
    fn test_verify_signature_fail() {
        let keys_file = "./results/test_verify_signature_fail_frost_keys.json";
        let signature_file = "./results/test_verify_signature_fail_signature.json";
        let result = generate_keys(3, 5, keys_file);
        assert!(result.is_ok(), "Failed to generate keys with t=3, n=5: {:?}", result.err());
        let message = "hi, this is a test";
        let result = sign_message(message, 3, 5, &keys_file, &signature_file);
        assert!(result.is_ok(), "Failed to sign message with t=3, n=5: {:?}", result.err());
        let result = validate_signature("different message", &keys_file, &signature_file);
        assert!(result.is_err(), "Verification should fail for a different message");
        remove_file(keys_file).unwrap();
        remove_file(signature_file).unwrap();
    }
}