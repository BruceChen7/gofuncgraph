#! /usr/bin/env python3

import os
import re
import argparse
import subprocess
import dataclasses

# The pattern is looking for a sequence of characters that starts with one or more word characters (`\w`), 
# followed by any characters (`.+?`) that are not white space (`\S`), then followed by one or more white space characters (`\s+`). 
# After the white space, there should be a semicolon (`;`). 
# Finally, there is a comment pattern (`/\*\s+`) followed by a number pattern (`\d+`).

# struct main.Person {
# 	struct string              Name;                 /*     0    16 */
# 	struct string              Address;              /*    16    16 */
# 	struct string              Phone;                /*    32    16 */
# 	int                        Age;                  /*    48     8 */
#
# 	/* size: 56, cachelines: 1, members: 4 */
# 	/* last cacheline: 56 bytes */
# };
PAT = re.compile(r"(?P<type>\w.+?\S)\s+(?P<name>\w+);\s+/\*\s+(?P<offset>\d+)")

parser = argparse.ArgumentParser(prog="offset_finder")
parser.add_argument("--bin", action="store", required=True)
parser.add_argument("--expr", action="store", required=True)


@dataclasses.dataclass
class Member:
    name: str
    type: str
    is_pointer: bool
    offset: int


def pahole(struct: str, field: str) -> (int, bool):
    proc = subprocess.Popen(
        ["pahole", "-C", struct, args.bin],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    for line in proc.stdout:
        if match := PAT.search(line.decode()):
            matchgroup = match.groupdict()
            if matchgroup["name"] != field:
                continue
            is_pointer = matchgroup["type"].endswith("*")
            type = (
                matchgroup["type"].removeprefix("struct ").removesuffix(" *")
            )
            return Member(
                name=field,
                type=type,
                is_pointer=is_pointer,
                offset=int(matchgroup["offset"]),
            )


if __name__ == "__main__":
    args = parser.parse_args()
    struct, *fields = args.expr.split("->")

    offsets = []  # [0, 1, 2] means +2(+1(+0(_)))
    last_type_is_pointer = True
    for field in fields:
        if not (member := pahole(struct, field)):
            raise ValueError(f"{struct}->{field} not found")
        print(member)
        if last_type_is_pointer:
            offsets.append(member.offset)
        else:
            offsets[-1] += member.offset
        struct = member.type
        last_type_is_pointer = member.is_pointer

    os.system(
        f"pahole -C '{struct}' {args.bin} 2>/dev/null",
    )

    res = "_"
    for offset in offsets:
        res = f"+{offset}({res})"
    print(res)
