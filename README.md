# codebreaker_t9
This was my implemented solution to the final challenge in the NSA codebreakers challenge.

## Context

The NSA Codebreaker Challenge is a series of 10 problems (zero indexed) held annually by the NSA each year, doubling both as a light-hearted cybersecurity puzzle event and recruiting mechanism. The code included in this repo reflects my solution for the culminating 10th task, "Task 9".

At this point in the challenge, the narrative structure had required assisting a victim of a ransomware attack. The tenth and final task necessitated using the disparate pieces of knowledge we had collected over time in order to crack the encryption key used by the attackers. To do this, we needed to decrypt a PDF file that was supplied.

The contents of this repository include a modified version of that PDF (id.pdf.enc); the original encrypted PDF included a number of appended bytes reflecting the IV used in the AES CBC cipher.

## Description

To run this program:

```
python3 -B crack.py
```

The **crack.py** program leverages multiprocessing across 4 CPUs to split up the work of iteratively checking every 8-digit hex number from 00000000-ffffffff. When it finds the correct one, it terminates the multiprocessing pool and produces the decrypted version of the pdf file (**decrypted.pdf**). The key is considered "correct" if the first few magic bytes of the decrypted file would be **%PDF**.
