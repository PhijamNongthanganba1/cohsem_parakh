from pathlib import Path
import re
import tokenize
from io import StringIO


# ============================================================
# PROJECT SETTINGS
# ============================================================

PROJECT_FOLDER = Path(__file__).parent

SKIP_FOLDERS = {
    ".git",
    "venv",
    ".venv",
    "env",
    "__pycache__",
    "node_modules"
}


# ============================================================
# REMOVE HTML COMMENTS
# ============================================================

def remove_html_comments(text):

    return re.sub(
        r"<!--[\s\S]*?-->",
        "",
        text
    )


# ============================================================
# REMOVE // AND /* */ COMMENTS
# Used for JS, TS and CSS
# ============================================================

def remove_slash_comments(text):

    result = []

    i = 0
    length = len(text)

    in_string = False
    string_char = None

    in_template = False
    in_line_comment = False
    in_block_comment = False

    while i < length:

        char = text[i]

        next_char = (
            text[i + 1]
            if i + 1 < length
            else ""
        )

        # ----------------------------------------------------
        # INSIDE // COMMENT
        # ----------------------------------------------------

        if in_line_comment:

            if char == "\n":

                in_line_comment = False
                result.append("\n")

            elif char == "\r":

                in_line_comment = False
                result.append("\r")

            i += 1
            continue


        # ----------------------------------------------------
        # INSIDE /* COMMENT */
        # ----------------------------------------------------

        if in_block_comment:

            if char == "*" and next_char == "/":

                in_block_comment = False

                i += 2
                continue

            if char == "\n":

                result.append("\n")

            elif char == "\r":

                result.append("\r")

            i += 1
            continue


        # ----------------------------------------------------
        # INSIDE STRING
        # ----------------------------------------------------

        if in_string:

            result.append(char)

            if char == "\\" and i + 1 < length:

                result.append(
                    text[i + 1]
                )

                i += 2
                continue

            if char == string_char:

                in_string = False
                string_char = None

            i += 1
            continue


        # ----------------------------------------------------
        # INSIDE TEMPLATE STRING
        # ----------------------------------------------------

        if in_template:

            result.append(char)

            if char == "\\" and i + 1 < length:

                result.append(
                    text[i + 1]
                )

                i += 2
                continue

            if char == "`":

                in_template = False

            i += 1
            continue


        # ----------------------------------------------------
        # START STRING
        # ----------------------------------------------------

        if char == '"' or char == "'":

            in_string = True
            string_char = char

            result.append(char)

            i += 1
            continue


        # ----------------------------------------------------
        # START TEMPLATE STRING
        # ----------------------------------------------------

        if char == "`":

            in_template = True

            result.append(char)

            i += 1
            continue


        # ----------------------------------------------------
        # START // COMMENT
        # ----------------------------------------------------

        if char == "/" and next_char == "/":

            in_line_comment = True

            i += 2
            continue


        # ----------------------------------------------------
        # START /* COMMENT */
        # ----------------------------------------------------

        if char == "/" and next_char == "*":

            in_block_comment = True

            i += 2
            continue


        # ----------------------------------------------------
        # NORMAL CHARACTER
        # ----------------------------------------------------

        result.append(char)

        i += 1

    return "".join(result)


# ============================================================
# REMOVE # COMMENTS FROM HTML / OTHER FILES
# Only removes lines whose first real character is #
# ============================================================

def remove_hash_comments(text):

    lines = text.splitlines(
        keepends=True
    )

    result = []

    for line in lines:

        stripped = line.lstrip()

        if stripped.startswith("#"):

            if line.endswith("\r\n"):
                result.append("\r\n")

            elif line.endswith("\n"):
                result.append("\n")

            elif line.endswith("\r"):
                result.append("\r")

            else:
                result.append("")

            continue

        result.append(line)

    return "".join(result)


# ============================================================
# PYTHON COMMENTS
# ============================================================

def remove_python_comments(text):

    lines = text.splitlines(
        keepends=True
    )

    comments = {}

    try:

        tokens = tokenize.generate_tokens(
            StringIO(text).readline
        )

        for token in tokens:

            if token.type == tokenize.COMMENT:

                line_number = token.start[0]
                column = token.start[1]

                comments.setdefault(
                    line_number,
                    []
                ).append(column)

    except Exception as e:

        print(
            "[PYTHON TOKEN ERROR]",
            e
        )

        return text


    result = []

    for number, line in enumerate(
        lines,
        start=1
    ):

        if number not in comments:

            result.append(line)

            continue


        for column in sorted(
            comments[number],
            reverse=True
        ):

            before = line[:column]

            if line.endswith("\r\n"):
                newline = "\r\n"

            elif line.endswith("\n"):
                newline = "\n"

            elif line.endswith("\r"):
                newline = "\r"

            else:
                newline = ""


            if before.strip():

                line = (
                    before.rstrip()
                    + newline
                )

            else:

                line = ""


        result.append(line)


    return "".join(result)


# ============================================================
# REMOVE PYTHON print(...)
#
# Handles:
#
# print("hello")
# print("hello", name)
# print(variable)
#
# Multi-line:
#
# print(
#     "hello",
#     name
# )
#
# Also:
#
#     print("hello")
#
# ============================================================

def remove_python_prints(text):

    try:

        tokens = list(
            tokenize.generate_tokens(
                StringIO(text).readline
            )
        )

    except Exception as e:

        print(
            "[PRINT TOKEN ERROR]",
            e
        )

        return text


    ranges = []

    i = 0

    while i < len(tokens):

        token = tokens[i]

        # Find NAME token "print"
        if (
            token.type == tokenize.NAME
            and token.string == "print"
        ):

            # Check next meaningful token
            j = i + 1

            while j < len(tokens):

                if tokens[j].type in (
                    tokenize.INDENT,
                    tokenize.DEDENT,
                    tokenize.NL,
                    tokenize.NEWLINE,
                    tokenize.COMMENT
                ):

                    j += 1
                    continue

                break


            if j < len(tokens):

                next_token = tokens[j]

                # Must be print(...)
                if (
                    next_token.type == tokenize.OP
                    and next_token.string == "("
                ):

                    depth = 0
                    end_token = None

                    k = j

                    while k < len(tokens):

                        current = tokens[k]

                        if (
                            current.type == tokenize.OP
                            and current.string == "("
                        ):

                            depth += 1


                        elif (
                            current.type == tokenize.OP
                            and current.string == ")"
                        ):

                            depth -= 1

                            if depth == 0:

                                end_token = current
                                break

                        k += 1


                    if end_token:

                        start_line = token.start[0]
                        start_col = token.start[1]

                        end_line = end_token.end[0]
                        end_col = end_token.end[1]

                        ranges.append(
                            (
                                start_line,
                                start_col,
                                end_line,
                                end_col
                            )
                        )

                        i = k

        i += 1


    if not ranges:
        return text


    lines = text.splitlines(
        keepends=True
    )


    # Remove from bottom to top
    for (
        start_line,
        start_col,
        end_line,
        end_col
    ) in reversed(ranges):

        if start_line == end_line:

            line = lines[start_line - 1]

            lines[start_line - 1] = (
                line[:start_col]
                + line[end_col:]
            )

        else:

            first = lines[start_line - 1]
            last = lines[end_line - 1]

            prefix = first[:start_col]
            suffix = last[end_col:]

            replacement = prefix + suffix

            lines[
                start_line - 1:end_line
            ] = [replacement]


    return "".join(lines)


# ============================================================
# CLEAN HTML
# ============================================================

def clean_html(text):

    # HTML <!-- -->
    text = remove_html_comments(text)

    # JavaScript // and /* */
    text = remove_slash_comments(text)

    # Remove lines beginning with #
    text = remove_hash_comments(text)

    return text


# ============================================================
# CLEAN PYTHON
# ============================================================

def clean_python(text):

    # First remove print(...)
    text = remove_python_prints(text)

    # Then remove Python # comments
    text = remove_python_comments(text)

    return text


# ============================================================
# PROCESS ONE FILE
# ============================================================

def process_file(file):

    try:

        text = file.read_text(
            encoding="utf-8"
        )

        original = text

        extension = file.suffix.lower()


        # ----------------------------------------------------
        # PYTHON
        # ----------------------------------------------------

        if extension == ".py":

            text = clean_python(text)


        # ----------------------------------------------------
        # HTML
        # ----------------------------------------------------

        elif extension in (
            ".html",
            ".htm"
        ):

            text = clean_html(text)


        # ----------------------------------------------------
        # CSS
        # ----------------------------------------------------

        elif extension == ".css":

            text = remove_slash_comments(text)


        # ----------------------------------------------------
        # JAVASCRIPT / TYPESCRIPT
        # ----------------------------------------------------

        elif extension in (
            ".js",
            ".jsx",
            ".ts",
            ".tsx"
        ):

            text = remove_slash_comments(text)


        else:

            return False


        # ----------------------------------------------------
        # SAVE
        # ----------------------------------------------------

        if text != original:

            file.write_text(
                text,
                encoding="utf-8"
            )

            return True


        return False


    except Exception as e:

        print(
            "[ERROR]",
            file,
            e
        )

        return False


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 70)
    print("FULL PROJECT CLEANER")
    print("=" * 70)
    print()
    print("Removing:")
    print("  # Python comments")
    print("  <!-- HTML comments -->")
    print("  // JavaScript comments")
    print("  /* CSS/JS comments */")
    print("  print(...) statements")
    print()
    print("=" * 70)
    print()


    extensions = {
        ".py",
        ".html",
        ".htm",
        ".css",
        ".js",
        ".jsx",
        ".ts",
        ".tsx"
    }


    checked = 0
    cleaned = 0


    for file in PROJECT_FOLDER.rglob("*"):

        if not file.is_file():
            continue


        # Skip folders
        if any(
            folder in file.parts
            for folder in SKIP_FOLDERS
        ):

            continue


        # Only supported files
        if file.suffix.lower() not in extensions:

            continue


        # Don't modify this cleaner
        if file.resolve() == Path(
            __file__
        ).resolve():

            continue


        checked += 1


        if process_file(file):

            cleaned += 1

            print(
                "[CLEANED]",
                file
            )

        else:

            print(
                "[NO CHANGE]",
                file
            )


    print()
    print("=" * 70)
    print("FINISHED")
    print("=" * 70)
    print()
    print(
        "Files checked :",
        checked
    )
    print(
        "Files cleaned :",
        cleaned
    )
    print()


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    main()