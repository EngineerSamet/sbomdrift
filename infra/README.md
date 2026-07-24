# infra

Terraform for everything this project uses in AWS. Roughly forty resources, no
compute, and deliberately **no VPC**.

## Why there is no VPC

The first draft of the architecture budgeted for three interface VPC endpoints,
copied from a cost-optimisation blog post. It was wrong: **nothing in this
project runs inside AWS.** GitHub-hosted runners are outside the account and
reach ECR over the public internet, so there is no VPC traffic to route and
nothing for an endpoint to save. Interface endpoints would have cost roughly
$14/month to carry zero bytes — and ECR's own documentation notes that a
pull-through cache behind an interface endpoint needs a NAT gateway for the
first pull, so the endpoints would have dragged a NAT back in too.

"I removed the VPC because nothing needed it" is a better answer than three
endpoints nobody could justify.

## Bootstrap, once

```bash
bash bootstrap/create-state-bucket.sh   # the one resource Terraform cannot create for itself
terraform init
terraform apply
```

## Then, by hand, in this order

The identity model (`identity.tf`) cannot be finished by Terraform without
risking a lockout, so the last two steps are manual and the order matters:

1. **Register an MFA device** for the IAM user, in the console.
   → IAM → Users → *samet* → Security credentials → Assign MFA device
2. **Verify the role opens** before taking anything away:
   ```bash
   aws sts assume-role \
     --role-arn "$(terraform output -raw admin_role_arn)" \
     --role-session-name check \
     --serial-number arn:aws:iam::<account>:mfa/<device> \
     --token-code 123456
   ```
3. **Only then** attach `assume_admin_policy_arn` to the user and remove that
   user from the `admin` group. Doing this before step 2 succeeds locks the
   account out of itself, and recovering needs the root credentials.

## Cost

| Resource | Cost |
|---|---|
| ECR storage | ~$1/month — billed per unique compressed layer, and the fleet shares base layers |
| S3 (state + drift database) | cents |
| IAM, OIDC provider, Budgets | free |
| **Inspector** | ~$0.09 per initial scan, ~$0.01 per re-scan — **off by default** |

Switch the referee on only for the measurement:

```bash
terraform apply -var enable_inspector=true
# ... run the oracle-agreement evaluation ...
terraform apply -var enable_inspector=false
```

`terraform destroy` removes everything except the state bucket, which is
intentionally outside Terraform's control.

## GitHub side

Set the CI role once, as a repository variable:

```bash
gh variable set AWS_ROLE_ARN --body "$(terraform output -raw github_ci_role_arn)"
```

There is no corresponding secret, because there is no key. That is the point.
