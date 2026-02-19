# VMProtect Devirtualization Challenges

![vmp-chall](image/vmp-chall.png)

This repository contains practice binaries for learning and experimenting with VMProtect devirtualization.

The samples are intentionally controlled and simplified to allow you to focus on understanding the virtualization layer and removing it cleanly. Additional levels with increased protection complexity may be added in the future.

---

## Targets

- `(Lv01)-chall-x64.exe` — x86-64
- `(Lv01)-chall-x86.vmp.exe` — x86 (32-bit)

More levels will be introduced over time.

---

## General Objective

For each level:

- Identify the virtualized function
- Recover its original native logic
- Patch the binary so execution no longer goes through the VMProtect interpreter
- Preserve the original program behavior

The goal is **not** to change functionality, but to remove the VM layer while keeping the same result.

---

## Level 01 (Overview)

When executed, the program displays a simple window.

Active keys:

- `ESC` — Exit
- `1` — Execute the protected `verify_key` function

If the expected result is produced, a success dialog is shown:

If you have devirtualized, Success!
Result: 0x469D4DF1


Note:

The original binary also prints this message because the VM engine executes the correct logic.  
Your task is to replace the VM entry with recovered native code so the same result is produced **without executing the VM interpreter**.

---

## Disclaimer

These binaries are provided for educational and research purposes only.
