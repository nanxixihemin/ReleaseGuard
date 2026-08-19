def format_release_name(name: str) -> str:
    return f"Release candidate: {name.strip()}"


if __name__ == "__main__":
    print(format_release_name("clean fixture"))
