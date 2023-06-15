# Digital-Forensics-and-Steganography-Recovering-Hidden-Data-from-a-JPG-Image

# A complete end-to-end investigation demonstrating steganography, file deletion simulation, disk forensics, and data recovery techniques.
Overview
This project walks through embedding hidden data inside a JPG using steganography, deleting the file to simulate an insider threat or anti-forensic attempt, and performing full forensic recovery using disk analysis tools.
The workflow mirrors how incident response teams uncover covert communication channels or retrieve intentionally destroyed evidence.

# Objectives
• Embed secret text into a JPG using steganography
• Simulate real-world deletion and data hiding
• Create a disk image capturing the deleted state
• Perform forensic recovery using FTK or equivalent
• Extract and validate the hidden message
• Document the full digital forensic chain of custody

# Environment
• Windows 10 forensic workstation
• SilentEye (for embedding and extraction)
• FTK Imager (for image creation and recovery)
• Dual-disk simulation (Logical Disk 1 and Disk 2)
• JPG carrier image (sufficient capacity for payload)

# Tools Used
• Steghide
• FTK Imager
• Hex viewer (optional)
• Disk management utilities
• Windows file system (NTFS)
• Evidence container formats (E01, RAW)

# Methodology

# 1. Steganographic Embedding
• Selected a larger JPG suitable for hiding text
• Embedded secret message inside the image using SilentEye’s LSB (Least Significant Bit) method
• Exported the stego image
• Verified the payload is retrievable before deletion

# 2. Evidence Destruction Simulation
• Deleted the stego JPG from the host file system
• Emptied recycle bin to simulate hard deletion
• Ensured the file no longer appears in Explorer

# 3. Disk Imaging
• Used FTK Imager to capture a full forensic image:
• Disk 1: OS + deleted file
• Disk 2: Simulated secondary storage
• Selected appropriate acquisition type (RAW or E01)
• Verified image integrity through MD5/SHA-1 hashing
• Ensured evidence preservation with no contamination

# 4. Forensic Recovery
• Loaded the RAW/E01 image into FTK
• Navigated unallocated space to locate remnants of the JPG
• Extracted the recovered JPG from slack space
• Validated integrity and identified readable data

# 5. Hidden Data Extraction
• Opened the recovered JPG in SilentEye
• Extracted the hidden text payload
• Confirmed that LSB embedding persisted through deletion and recovery
• Documented the recovered message as forensic evidence

# Key Findings
Deleted JPG files remain recoverable via unallocated space
Steganographic payloads survive file deletion
Windows recycle bin deletion is insufficient for secure erasure
Disk imaging ensures evidentiary integrity
Combining steganography with forensic techniques reveals covert channels

# Recommendations
• Implement secure wiping tools for sensitive data
• Monitor for unusual JPG modifications in high-risk environments
• Restrict unauthorized use of steganographic applications
• Enable endpoint monitoring for file deletion events
• Perform regular forensic readiness training

/Digital-Forensics-Steganography
│
├── carrier/
│   ├── original.jpg
│   └── stego.jpg
│
├── evidence/
│   ├── disk1.E01
│   ├── disk2.E01
│   ├── hashes.txt
│
├── recovery/
│   ├── recovered-stego.jpg
│   ├── extracted-message.txt
│
└── README.md

# Author
Developed by Gresa Hisa (@gresium)
AI & Cybersecurity Engineer 
GitHub: https://github.com/gresium



