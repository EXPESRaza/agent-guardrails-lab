"""Test model validation logic"""

def test_model_validation():
    valid_models = [
        "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4",
        "gpt-3.5-turbo", "gpt-3.5-turbo-16k",
        "o1-preview", "o1-mini"
    ]

    # Test cases
    test_cases = [
        ("gpt-4o-mini", True, "Valid model from .env"),
        ("gpt-4o", True, "Valid GPT-4o model"),
        ("gpt-3.5-turbo", True, "Valid GPT-3.5 model"),
        ("gpt-5", False, "Invalid model - doesn't exist"),
        ("claude-3", False, "Invalid - wrong provider"),
        ("GPT-4O-MINI", False, "Invalid - case sensitive"),
        ("gpt-4o-mini-new", False, "Invalid - not in list"),
        ("", False, "Empty model name"),
    ]

    print("=" * 60)
    print("MODEL VALIDATION TEST")
    print("=" * 60)

    for model_name, should_pass, description in test_cases:
        is_valid = model_name.strip() in valid_models if model_name.strip() else False
        status = "[PASS]" if is_valid == should_pass else "[FAIL]"
        result = "VALID" if is_valid else "INVALID"

        print(f"\n{status} | Model: '{model_name}'")
        print(f"      Description: {description}")
        print(f"      Result: {result}")
        if not is_valid and model_name.strip():
            print(f"      Error: Invalid model. Valid models: {', '.join(valid_models)}")

    print("\n" + "=" * 60)

if __name__ == "__main__":
    test_model_validation()
