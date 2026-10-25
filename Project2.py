"""Access-control matrix: display MAC.txt and administer it.

Rows are subjects (users), columns are files.
Permission values: r (read), r/w (read and write), np (no permission).
"""

import os
import sys

MAC_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "MAC.txt")
VALID_PERMS = ("r", "r/w", "np")


# ---------- storage ----------

def load_matrix(path=MAC_FILE):
    """Read MAC.txt and return (files, {subject: {file: perm}})."""
    with open(path) as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    header = [c.strip() for c in lines[0].split("|")]
    files = header[1:]
    matrix = {}
    for line in lines[1:]:
        if set(line) <= set("-+| "):          # separator row
            continue
        cells = [c.strip() for c in line.split("|")]
        matrix[cells[0]] = dict(zip(files, cells[1:]))
    return files, matrix


def render(files, matrix):
    """Return the matrix as an aligned text table."""
    header = ["Subjects"] + files
    rows = [[subj] + [perms[fn] for fn in files] for subj, perms in matrix.items()]
    widths = [max(len(r[i]) for r in [header] + rows) for i in range(len(header))]

    def fmt(cells):
        return " | ".join(c.ljust(w) for c, w in zip(cells, widths)).rstrip()

    sep = "-+-".join("-" * w for w in widths)
    return "\n".join([fmt(header), sep] + [fmt(r) for r in rows]) + "\n"


def save_matrix(files, matrix, path=MAC_FILE):
    with open(path, "w") as f:
        f.write(render(files, matrix))


def display(path=MAC_FILE):
    with open(path) as f:
        print("\n" + f.read())


# ---------- admin operations ----------

def add_subject(files, matrix, name, perms=None):
    """Add a subject row. perms maps file -> permission; default is np."""
    name = name.strip()
    if not name:
        raise ValueError("Subject name cannot be empty.")
    if "|" in name:
        raise ValueError("Subject name cannot contain '|'.")
    if name.lower() in (s.lower() for s in matrix):
        raise ValueError(f"Subject '{name}' already exists.")
    perms = perms or {}
    row = {}
    for fname in files:
        p = perms.get(fname, "np")
        if p not in VALID_PERMS:
            raise ValueError(f"Invalid permission '{p}'. Use one of {VALID_PERMS}.")
        row[fname] = p
    matrix[name] = row


def update_permission(files, matrix, subject, fname, perm):
    if subject not in matrix:
        raise ValueError(f"Unknown subject '{subject}'.")
    if fname not in files:
        raise ValueError(f"Unknown file '{fname}'.")
    if perm not in VALID_PERMS:
        raise ValueError(f"Invalid permission '{perm}'. Use one of {VALID_PERMS}.")
    matrix[subject][fname] = perm


# ---------- access checking / authorization ----------

READ, WRITE = "read", "write"
GRANTS = {"r": {READ}, "r/w": {READ, WRITE}, "np": set()}


def authorize(files, matrix, subject, fname, action):
    """Check whether `subject` may perform `action` (read/write) on `fname`.

    Returns (allowed, reason). Fails closed: an unknown subject, file,
    action or permission value is always denied.
    """
    if subject not in matrix:
        return False, f"unknown subject '{subject}'"
    if fname not in files:
        return False, f"unknown file '{fname}'"
    if action not in (READ, WRITE):
        return False, f"unknown action '{action}' (use '{READ}' or '{WRITE}')"
    perm = matrix[subject].get(fname, "np")
    if perm not in GRANTS:
        return False, f"unrecognized permission '{perm}'"
    if action in GRANTS[perm]:
        return True, f"permission '{perm}' allows {action}"
    return False, f"permission '{perm}' does not allow {action}"


def access_report(files, matrix):
    """Authorize every subject for read and write on every file.

    Returns {subject: {file: {"read": bool, "write": bool}}}.
    """
    return {
        subj: {
            fn: {a: authorize(files, matrix, subj, fn, a)[0] for a in (READ, WRITE)}
            for fn in files
        }
        for subj in matrix
    }


def print_access_report(files, matrix):
    report = access_report(files, matrix)
    name_w = max(len("Subjects"), *(len(s) for s in report))
    col_w = max(len(fn) for fn in files)
    print("\nAccess report (RW = read+write, R- = read only, -- = no access)")
    print("Subjects".ljust(name_w) + " | " + " | ".join(fn.ljust(col_w) for fn in files))
    print("-" * name_w + "-+-" + "-+-".join("-" * col_w for _ in files))
    for subj, row in report.items():
        cells = []
        for fn in files:
            r, w = row[fn][READ], row[fn][WRITE]
            cells.append(("R" if r else "-") + ("W" if w else "-"))
        print(subj.ljust(name_w) + " | " + " | ".join(c.ljust(col_w) for c in cells))


# ---------- admin interface ----------

def pick(prompt, options):
    """Let the admin choose an option by number or by name."""
    for i, opt in enumerate(options, 1):
        print(f"  {i}. {opt}")
    raw = input(prompt).strip()
    if raw.isdigit() and 1 <= int(raw) <= len(options):
        return options[int(raw) - 1]
    for opt in options:
        if opt.lower() == raw.lower():
            return opt
    raise ValueError(f"'{raw}' is not a valid choice.")


def ask_permission(prompt):
    raw = input(prompt).strip().lower()
    if raw not in VALID_PERMS:
        raise ValueError(f"Invalid permission '{raw}'. Use one of {VALID_PERMS}.")
    return raw


def parse_entry(files, entry):
    """Parse 'Name_p1_p2_..._pN' into (name, {file: perm}).

    The last len(files) underscore-separated tokens are the permissions
    (in file order); everything before them is the name, so names that
    contain underscores still work.
    """
    parts = entry.strip().split("_")
    n = len(files)
    if len(parts) < n + 1:
        raise ValueError(
            f"Expected a name followed by {n} permissions, e.g. "
            "Fanny_np_r/w_r_r_r"
        )
    name = "_".join(parts[:-n])
    perms = [p.strip().lower() for p in parts[-n:]]
    for p in perms:
        if p not in VALID_PERMS:
            raise ValueError(f"Invalid permission '{p}'. Use one of {VALID_PERMS}.")
    return name, dict(zip(files, perms))


PERM_HELP = "r = read only, r/w = read and write, np = no permission"


def create_user(files, matrix):
    print(f"Permissions: {PERM_HELP}")
    print(f"Enter the new user as Name_<{len(files)} permissions>, "
          "e.g. Fanny_np_r/w_r_r_r")
    print(f"  (permissions are in file order: {', '.join(files)})")
    print("Or press Enter to be asked for the name and each permission.")
    entry = input("Input: ").strip()
    if entry:
        name, perms = parse_entry(files, entry)
    else:
        name = input("New user name: ").strip()
        perms = {}
        print(f"Permission for each file ({PERM_HELP}). Press Enter for np.")
        for fname in files:
            raw = input(f"  {fname}: ").strip().lower()
            if raw:
                perms[fname] = raw
    add_subject(files, matrix, name, perms)
    save_matrix(files, matrix)
    print("\nUpdated access control matrix:")
    display()


DATA_DIR = os.path.dirname(MAC_FILE)


def resolve_file(files, token):
    """Map 'File1' / 'file 1' to the matrix column name 'File 1'."""
    key = token.replace(" ", "").lower()
    for fn in files:
        if fn.replace(" ", "").lower() == key:
            return fn
    return None


def data_path(fname):
    """'File 1' -> <dir>/File 1.txt (falls back to File1.txt if only that exists)."""
    primary = os.path.join(DATA_DIR, fname + ".txt")
    if os.path.exists(primary):
        return primary
    alternate = os.path.join(DATA_DIR, fname.replace(" ", "") + ".txt")
    return alternate if os.path.exists(alternate) else primary


def resolve_request(files, matrix, entry):
    """Parse 'Subject_File' (e.g. Alice_File1, alice_file 1).

    Returns (subject, fname, problem). `problem` is None on success, otherwise
    a short reason such as "unknown subject 'Zed'".
    """
    if "_" not in entry:
        raise ValueError("Expected Subject_File, e.g. Alice_File1 (or 'Admin').")
    subj_tok, file_tok = entry.strip().rsplit("_", 1)
    subject = next((s for s in matrix if s.lower() == subj_tok.strip().lower()), None)
    fname = resolve_file(files, file_tok)
    if subject is None:
        return None, None, f"unknown subject '{subj_tok}'"
    if fname is None:
        return subject, None, f"unknown file '{file_tok}'"
    return subject, fname, None


def permission_summary(files, matrix, subject, fname):
    """Both permissions for one subject/file pair, as human-readable text."""
    can_read = authorize(files, matrix, subject, fname, READ)[0]
    can_write = authorize(files, matrix, subject, fname, WRITE)[0]
    return (f"{subject} on {fname} (permission '{matrix[subject][fname]}'):\n"
            f"  Read : {'ALLOWED' if can_read else 'DENIED'}\n"
            f"  Write: {'ALLOWED' if can_write else 'DENIED'}")


def request_access(files, matrix, entry):
    """Handle a 'Subject_FileN' request (e.g. Alice_File1).

    - no permission: print NO PERMISSION; the file is never opened or printed
    - r:   print the file's contents; write access is denied
    - r/w: print the file's contents and open it for reading and writing
    """
    subject, fname, problem = resolve_request(files, matrix, entry)
    if problem:
        print(f"NO PERMISSION ({problem})")
        return

    can_read = authorize(files, matrix, subject, fname, READ)[0]
    can_write = authorize(files, matrix, subject, fname, WRITE)[0]
    if not can_read:
        print("NO PERMISSION")
        return

    path = data_path(fname)
    name = os.path.basename(path)
    if not os.path.exists(path):
        print(f"Error: {name} not found.")
        return

    with open(path, "r+" if can_write else "r") as f:
        content = f.read()
        print(f"\n--- {name} ---")
        print(content, end="" if content.endswith("\n") else "\n")
        print("--- end ---")
        if can_write:
            print(f"{name} is open for reading and writing "
                  f"({subject} has r/w access on {fname}).")
            try:
                text = input("Append text (press Enter to skip): ")
            except EOFError:
                text = ""
            if text:
                f.seek(0, os.SEEK_END)
                f.write(text + "\n")
                print(f"Saved to {name}.")
        else:
            print(f"Write access denied: {subject} has read-only (r) "
                  f"permission on {fname}.")


def admin_menu():
    files, matrix = load_matrix()
    while True:
        print("\nOptions:")
        print("  Create (1) - Add a new user and their permissions")
        print("  Update (2) - Update a user's permission on a file")
        print("  Check  (3) - View read/write permissions (e.g. Alice_File1)")
        print("  Report (4) - Access report for all users and files")
        print("  Show   (5) - Show the access control matrix")
        print("  Quit   (6)")
        choice = input("Input: ").strip()
        try:
            if choice == "1":
                create_user(files, matrix)
            elif choice == "2":
                subject = pick("Subject: ", list(matrix))
                fname = pick("File: ", files)
                print(f"Current permission: {matrix[subject][fname]}")
                perm = ask_permission("New permission (r, r/w, np): ")
                update_permission(files, matrix, subject, fname, perm)
                save_matrix(files, matrix)
                print(f"{subject} on {fname} is now '{perm}'. Saved to MAC.txt.")
                print("\nUpdated access control matrix:")
                display()
            elif choice == "3":
                print("Enter Subject_File to see read and write permissions, "
                      "e.g. Alice_File1")
                subject, fname, problem = resolve_request(
                    files, matrix, input("Input: ").strip())
                if problem:
                    print(f"NO PERMISSION ({problem})")
                else:
                    print(permission_summary(files, matrix, subject, fname))
            elif choice == "4":
                print_access_report(files, matrix)
            elif choice == "5":
                display()
            elif choice == "6":
                break
            else:
                print("Please enter 1-6.")
        except ValueError as e:
            print(f"Error: {e}")
        except (EOFError, KeyboardInterrupt):
            print()
            break


if __name__ == "__main__":
    if not os.path.exists(MAC_FILE):
        sys.exit(f"{MAC_FILE} not found.")
    files, matrix = load_matrix()
    print("\nAccess control matrix (from MAC.txt):")
    display()           # read MAC.txt and print the table
    print("=== Access Control System ===")
    print("Enter one of:")
    print("  Admin         - open the admin menu")
    print("  Subject_File  - open a file according to that subject's permissions, e.g. Alice_File1")
    print(f"Subjects: {', '.join(matrix)}")
    print(f"Files:    {', '.join(fn.replace(' ', '') for fn in files)}")
    entry = input("Input: ").strip()
    if entry.lower() == "admin":
        admin_menu()
    else:
        try:
            request_access(files, matrix, entry)
        except ValueError as e:
            sys.exit(f"Error: {e}")
