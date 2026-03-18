import argparse
import json

from colorama import Fore, Style, init

from scanner import IAMScanner


def print_scan(report: dict) -> None:
    for user in report["users"]:
        print(Fore.BLUE + f"User Name: {user['user_name']}" + Style.RESET_ALL)

        if not user["inline_policies"]:
            print(Fore.GREEN + " - No inline policies" + Style.RESET_ALL)
        else:
            print(" - User inline policies:")
            for policy in user["inline_policies"]:
                print(Fore.CYAN + f"   + {policy['name']}" + Style.RESET_ALL)
                for statement in policy["statements"]:
                    print(f"     Effect: {statement.get('effect')}")
                    for action in statement.get("actions", []):
                        print(f"       Action: {action}")

        if not user["managed_policies"]:
            print(Fore.GREEN + " - No managed policies" + Style.RESET_ALL)
        else:
            print(" - User managed policies:")
            for policy in user["managed_policies"]:
                print(Fore.CYAN + f"   + {policy['name']} ({policy['arn']})" + Style.RESET_ALL)

        if not user["groups"]:
            print(Fore.GREEN + " - No group membership" + Style.RESET_ALL)
        else:
            print(" - Groups:")
            for group in user["groups"]:
                print(Fore.MAGENTA + f"   + {group['name']}" + Style.RESET_ALL)

        print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan IAM permissions for all account users")
    parser.add_argument("--profile", help="AWS profile name", default=None)
    parser.add_argument("--region", help="AWS region (IAM is global, optional)", default=None)
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args()

    init(autoreset=True)
    report = IAMScanner(profile=args.profile, region=args.region).scan()

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print_scan(report)


if __name__ == "__main__":
    main()
