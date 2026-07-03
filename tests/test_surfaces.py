from __future__ import annotations

from agent_permission_diff_bot.surfaces import extract_atoms


def test_workflow_secret_name_does_not_create_deploy_atom() -> None:
    atoms = extract_atoms(
        ".github/workflows/secret.yml",
        """
name: Secret
on:
  workflow_dispatch:
jobs:
  expose:
    runs-on: ubuntu-latest
    steps:
      - run: echo "token=${{ secrets.DEPLOY_TOKEN }}" >> "$GITHUB_OUTPUT"
""",
    )

    assert any(atom.action == "credential" and atom.value == "DEPLOY_TOKEN" for atom in atoms)
    assert not any(atom.action == "cloud_deploy" for atom in atoms)


def test_workflow_deploy_command_still_creates_deploy_atom() -> None:
    atoms = extract_atoms(
        ".github/workflows/deploy.yml",
        """
name: Deploy
on:
  workflow_dispatch:
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: vercel deploy --prod
""",
    )

    assert any(atom.action == "cloud_deploy" for atom in atoms)
