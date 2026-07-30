+++
date = '2026-07-30T11:11:46+02:00'
author = "alarmfox"
draft = false
title = 'Held hostage by Cisco Netacad'
keywords = ["cisco", "netacad", "ai"]
+++

> **TLDR** This is just a rant about what it has been happening for 5 years and an excuse to think about how most of the AI will be (or is actually) used in real-world.

## Backstory

I joined a Cisco Networking Academy class back in 2019 using my personal email that did not change. Later on, I found a job and the company gave me a work email. Pretty normal. The company also proposed me to become a Cisco instructor for the Devnet (automation, networking, infrastructure stuff ~and Cisco marketing~). So here I am as a Devnet instructor (that certification does no exist anymore, but the skills are re-arranged in new courses). They enrolled me in the instructor program with my work email and I became instructor with that email.

## The nightmare

One year later, I left the job to get my MSc, but continued working with the teaching part. As soon as I left the job (beginning of 2023), the sysadmin deactivated my email, so when they proposed me to teach the course, I lost my instructor status.

First fight to get previous work email back (took 1 month).

Seeing the issue, I tried to migrate that account to my personal Gmail. **Wait!** Cisco police says you cannot do that! The account is already in use! I wrote emails, talked to people in the company I used to work and all I received was "We will let you know, we have to talk to Cisco".

![Email change](/static/images/held-hostage-by-cisco-netacad/email-change.png)

After some little waiting (~1 year~), no response. So, to keep my instructor things (not only the status, but materials and activities) and just to be a little independent I bought a temporary account (the one you see in the email) promising myself that I will the transfer whenever I had a free spot.

So, each summer or during Christmas holidays, I try to merge the accounts looking around for support emails etc. After 3 years, I am still:

- here paying for this email box
- I bought a domain
- brought up my personal infrastructure:
    + _traefik_ + a ton of services

But no merge yet.

## The death loop

But wait, now we are in the AI era everything should be simpler! Flexing my **ChatGPT Plus** (23€ per month (*sic!*)). Let's ask AI! So I opened the chat, chose *GPT-5.6 Sol (Medium)* and wrote:

> **PROMPT**> I have 2 cisco netacad accounts. One is capassog97@gmail.com that i used to join the Cisco Academy in 2019 and one created when i become an instructor.
>
> After i left I migrated the account to a paid inbox (i could not put the gmail because it was in use).
>
> Now i don't want to pay for the inbox anymore and I want to merge both accounts keeping all my instructor stuff and student certificate keeping all on my gmail accounts. What are the steps

The full chat is [here](https://chatgpt.com/share/6a6b2147-f90c-83eb-b3b5-9754c84eca16)

ChatGPT says write to support and prepares a good looking draft email like if I am asking for the grace to President. It even puts some links, but they all lead to the **Hell**. This _Morgan_ virtual assistant (wow it looks like Whatsapp! it must be good no?).

How was that called? User Experience? UI/UX? There you go:

![Morgan 1 screen](/static/images/held-hostage-by-cisco-netacad/morgan1.png)
![Morgan 2 screen](/static/images/held-hostage-by-cisco-netacad/morgan2.png)
![Morgan 3 screen](/static/images/held-hostage-by-cisco-netacad/morgan3.png)
![Morgan 4 screen](/static/images/held-hostage-by-cisco-netacad/morgan4.png)

After this pleasant experience, I went back to ChatGPT (hey I pay 23€ per month). All it managed to say is: reload the page and ask to create for a support case. Results below:

![Morgan 5 screen](/static/images/held-hostage-by-cisco-netacad/morgan5.png)

So we are stuck in a loop. I went online and found [this from 2026](https://community.cisco.com/t5/discuss%C3%B5es-geral/cisco-account-merge/m-p/5546824/highlight/true). Wow! this is just what I need. A human (maybe), answered that I need to go:

- <span id="web-help">web-help-portal</span>
- profile manager
- access management
- chat now
- write the magic words "Request assistance with merging my Cisco accounts"

Let's go! This is what I got following the procedure: a loop to the famous Cisco support at https://web-help.cisco.com! So go [here](#web-help) and do all the procedure yourself!

![Cisco AI](/static/images/held-hostage-by-cisco-netacad/ciscoai.png)

So I guess, I am just stuck in this loop? What have we become? How can I talk to someone?

## Recap

So I am stuck with 2 accounts. Neither Cisco community/documentation stuff works.

Companies do not care about Q/A, customer support. Everything that has a _minus_ sign in their excel sheet has to be lowered or removed. Putting a shitty chatbot helps in firing people so they will keep doing that. This is how most companies aim to use AI: reduce costs regardless of quality. This does not simply apply to Cisco. Lots of italian companies purposely create loops avoiding always to put an human when needed, because the "real person" does not even exists anymore.

I will make an attempt in December as always or when i see the _- ~13€_ bill per year to maintain an email account I cannot remove. Of course one can move to a free account (i did move to the free proton account btw) but **WHY**? Why can't I just use the email that I have for a mistake I did not even do myself?

At least I learned DevOps so that I manage my infrastructure with secret vaults, ansible playbooks, docker, traefik reverse proxy and Cloudflare.
