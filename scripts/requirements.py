import sys
import tomllib


def requirements(pyproject: dict, groups: list[str]) -> list[str]:
  project = pyproject["project"]
  known = {
    "build": pyproject["build-system"]["requires"],
    "runtime": project["dependencies"],
    **project["optional-dependencies"],
  }
  return [requirement for group in groups for requirement in known[group]]


if __name__ == "__main__":
  with open(sys.argv[1], "rb") as f:
    print("\n".join(requirements(tomllib.load(f), sys.argv[2:])))
