# Phrack 40th Anniversary CTF Challenge

## Challenge Introduction 

After hearing rumors that their C developers have taken up vibe coding to keep up with feature
requests, Infinite Loop Solutions Incorporated, a subsidiary of Deadlock Enterprises, wants a
thorough security review. They are challenging Phrack readers (aka the best hackers in the world) to
hack their products. ILS Inc. knows that even a small coding misstep could lead to remote code
execution or local privilege escalation, so they’ve implemented various secure practices. The first
one being -- obscurity!

Are you 1337 enough to hack into ILS?

## How To Play

Each challenge began with providing the vulnerable binary (very_normal_device.bin - Linux userland, AVeryNormalDriver.sys - Windows kernel) and instructions on how to access the machine running the vuln code. The players job was to create an exploit for both (RCE - Linux, LPE - Windows) to obtain the flags. 

## What's Here
I've included enough to recreate the environment to test your exploits. I've included the source code for both challenges, however I would highly recommend challenging yourself and trying to reverse engineer the binary as intended, first.  

## Solutions
I've included example solutions for each challenge. However, there are variety of ways each challenge can be solved, as they both contain multiple exploitable vulnerabilities. 

## Usage

I do not consent for any of this material to be used in a training course *or anywhere else* without my explicit permission. If you see anything contained in this repo somewhere else please report it to chompie1337@gmail.com. 
