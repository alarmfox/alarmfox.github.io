+++
date = '2025-12-12T21:53:33+01:00'
draft = false
title = 'The importance of tools'
readingTime = true
toc = true
+++

## Introduction
I have wanted to write this post for months.
During my mentor career, my life as student and, lately, during the Advent of Code 2025 I
noticed that many people are not limited by their intelligence, experience or ideas but what
they miss are: _**tools**_. In engineering, or anything related to creating things, tools are
the most important things to master, but not the way everyone thinks. This **is not** something about
being more productive.

> **What is a tool?**: for this blogpost a tool is something that solves a very specific problem. It can 
be software related (a library, an editor) or physical (an hammer).

## How do I view tools
Tools are the result of some of the most important phases when designing a solution to a problem:

- **modeling**: creating a tool requires focus on a very specific problem
- **usability**: thinking about users of the tool helps understanding the problem

What i like to do is to distinguish two aspects: using a tool and creating a tool. Both aspects 
are very formative especially when we are very young. Explore both next.

### Using a tool
Let's setup a very common case study.

We are learning programming and you want to understand the full building process. We want to do it 
with `vim` (like pros), using C, we want to do on Linux and we want to learn send a ping towards an IP address.

If you understand what I wrote you know that everyone trying something like this will end up in a 
barely working hello world program. This not because sending ICMP using C on Linux is difficult, but 
because you have not invested into understanding what the full game about programming is. Let's say
it like some yapping ~UML-fan~ would love to hear this. When I stated our goal, I missed something 
called like `non-functional` requirements (or as as non UML person I like to say something implicit).
These are all the assumptions we made:

- Networking knowledge: do we know what a ping is?
- Linux knowledge: do we know how to work with Linux networking?
- C knowledge: how much C do we need to do this?

Let's assume that we managed some way to get some network traffic out: **how** do we test this? Do
we need to check that we have another host that responds to ping? Is there a **tool** to do this?

There are different outcome from this:

* We know networking but we don't know Linux and C
* We know Linux but we don't know networking
* We know C but we don't know networking and Linux

Each of these gaps produces a different failure mode, and none of them can be fixed by guessing
or trial-and-error. The moment you step outside "hello world" the real work is no longer typing 
code but understanding the environment in which that code operates.
The tools-packet analyzers, debuggers, diagnostic utilities only become useful when you actually 
know what they are showing you. 

#### Personal experiences

Lately, I participated in Advent of Code and I struggled on **day 09** part 2, The problem was on 
something about [finding the maximum area of a rectangle fitting a non-convex poly line](https://adventofcode.com/2025/day/9).
The amount of time I spent before trying to look at the input graphically ended up in finishing my 
free time (i had to go back to work). That happened because i was not familiar with visual tool and 
did not know what to expect from that, what to look for, but once i looked at that i knew at least one 
strategy. The solution was something like this:

```c
/* Sort all rectangles by area */
qsort(rectangles, numrectangles, sizeof(struct rectangle), compare_by_area);

/* The first valid rectangle is the answer, we sort by area */
const struct rectangle *r = NULL;
for(int i = 0; i < numrectangles; ++i) {
    r = &rectangles[i];
    printf("(%d)Rectangle [(%ld, %ld), (%ld, %ld), (%ld, %ld), (%ld, %ld)]\n",
            i,
            r->a.x, r->a.y,
            r->b.x, r->b.y,
            r->c.x, r->c.y,
            r->d.x, r->d.y
          );
    if(is_inside(r, points, numpoints)) break;
}

return rect_area(r);
```

Speaking about networking: 90% (made up number) networking problems are solved by actually looking at the traffic. As I tell to my students, the beautiful thing about computer science and engineering it's that it is real: what we study in the book is reproduced on the wire. Have a look at a Wireshark capture of a live network and you will discover many details in it for free without using some ~fancy hackish~ programs on Kali Linux.

### Creating a tool
Citing another [blogpost](https://giuseppe.capass.org/tech-research-stuff/the-true-power-of-python-gdb/),
creating a tool is a way to understand deeply a problem. It is even better if you are writing the tool 
for yourself (it's hard to think that someone makes tools for other's problems).

## Fake tools: beware
The hard reality of this post is that: understand a topic cannot happen without doing something real.
If I read and yap about Harry Potter, I am not gonna become a wizard.

Good tools do not simplify or eliminate works, but they enforce a common vision on a problem providing 
for a solution: the `ip` command suite in Linux makes much sense when you fully understand networks and 
how Linux sees them. Is it perfect? Maybe not, but try to understand the mind and reason behind before judge.

If you find yourself with a "magical" tool and you are working on a serious project, you are going to regret using it in the future.
