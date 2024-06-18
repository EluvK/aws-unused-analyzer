# UnusedAnalyzer With AWS SDK

This project will be a simple implementation of the UnusedAnalyzer using the AWS SDK for Rust.

## What is UnusedAnalyzer

Here is an official blog post about [UnusedAnalyzer](https://aws.amazon.com/blogs/aws/iam-access-analyzer-updates-find-unused-access-check-policies-before-deployment/).

And it's documentation is [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html).

## Why This Project

After studying how the official UnusedAnalyzer works, I don’t quite understand why this feature was designed as a paid feature. After all, its core algorithm is to compare `if a - b > c`.

So I wanted to make a free version or it with [AWS SDK](https://github.com/awslabs/aws-sdk-rust).

## How to run

It's a CLI tools, with help message:

```bash
cargo run -- --help
Usage: aws-unused-analyzer [OPTIONS]

Options:
  -r, --region <REGION>                        
  -a, --access-key <ACCESS_KEY>                
  -s, --secret-key <SECRET_KEY>                
  -u, --unused-access-age <UNUSED_ACCESS_AGE>  [default: 90]
```

Instead of running with source code which require cargo toolchain, you can also run with release binary:

```bash
aws-unused-analyzer --help
```

### With Arguments Or With Environment Variables

```bash
aws-unused-analyzer --a <ACCESS_KEY> --s <SECRET_KEY> -u 30
```

It will use the arguments first, if not provided, it will use the environment variables.

how to set environment variables for AWS SDK: [doc](https://docs.aws.amazon.com/sdkref/latest/guide/environment-variables.html#envvars-set)

Wait for a while(depends on the number of IAM Users and Roles), you will get the output file in the current directory.

`echo unused_findings.json`

```json
{
  "resource": "arn:aws:iam::1234567890:role/TestRole",
  "resource_type": "AwsIamRole",
  "resource_owner_account": "1234567890",
  "id": "99f66ff9-5763-4e8f-9284-f2aebf3df753",
  "finding_details": [
    {
      "UnusedPermissionDetails": {
        "actions": null,
        "service_namespace": "s3",
        "last_accessed": "2024-02-29T12:37:10Z"
      }
    }
  ],
  "finding_type": "UnusedPermission"
}
```

## Roadmap

- [x] Implement the account unused analyzer generating same output as the official one.
- [ ] Implement the finding recommendation for UnusedPermission of Role. (updated at 6.18 re:Inforce 2024)
- [ ] Implement the organization unused analyzer feature (using user defined role maybe).
- [ ] ...to be finded out.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE-MIT) file for details.
