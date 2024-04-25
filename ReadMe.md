# UnusedAnalyzer With AWS SDK

This project will be a simple implementation of the UnusedAnalyzer using the AWS SDK for Rust.

currently on development...

## What is UnusedAnalyzer

Here is an official blog post about [UnusedAnalyzer](https://aws.amazon.com/blogs/aws/iam-access-analyzer-updates-find-unused-access-check-policies-before-deployment/).

And it's documentation is [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html).

## Why This Project

After studying how the official UnusedAnalyzer works, I don’t quite understand why this feature was designed as a paid feature. After all, its core algorithm is to compare `if a - b > c`.

So I wanted to implement it using the AWS SDK.

## How to run

### With Arguments

cargo run with arguments:

```bash
cargo run -- --access-key <ACCESS_KEY> --secret-key <SECRET_KEY>
```

or with release binary:

```bash
aws-unused-analyzer --access-key <ACCESS_KEY> --secret-key <SECRET_KEY>
```

### With environment variables

how to set environment variables for AWS SDK: [doc](https://docs.aws.amazon.com/sdkref/latest/guide/environment-variables.html#envvars-set)

## Roadmap

- [ ] Implement the account unused analyzer generating same output as the official one.
- [ ] Implement the organization unused analyzer feature (using user defined role maybe).
- [ ] ...to be find out.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE-MIT) file for details.
