# GitHub Organization Setup

Use a GitHub Organization named after the final product or company. Do not create another personal login.

1. Create the organization from the founder's existing `nemo-wq` account.
2. Require two-factor authentication and add a separate recovery owner when a trusted co-maintainer is available.
3. Transfer `nemo-wq/AWS-IAM-Permissions-Scanner` into the organization and rename it `iam-exposure`.
4. Create `iam-exposure-cloud` as a private repository with access limited to the Cloud team.
5. Rename the default branch to `main`, require pull requests and passing CI, prevent force pushes, and require signed release tags.
6. Enable private vulnerability reporting, Dependabot, secret scanning, and push protection.
7. Configure PyPI trusted publishing for the release workflow without storing a PyPI token.
8. Set Pages source to GitHub Actions so the synthetic report workflow can publish the live example.

After the organization transfer, update the Pages URL in `README.md` to the organization's new Pages hostname. Repository redirects do not guarantee that the old Pages hostname will follow the transfer.

Keep the founder's personal account visible as maintainer. The organization provides the brand, access control, billing, and future team boundary.
