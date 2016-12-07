---
layout: post
title: SQL Injection
comments: true
excerpt: In this post we cover the three categories of SQL Injection and detail and provide examples for four types of SQLi attacks.
---

## What is a SQL

Structured Query Language (SQL) is a language used to interact with
relational database management systems (RDBMS) such as MySQL, PostgreSQL, Oracle
SQL, etc. Through this language programmers and administrators are able to
administer databases as well as modify their data. Data can be selected,
updated, inserted or deleted based on conditions through SQL.

Applications often rely on information given by a user when creating a query.
This information can be a product id given in a link, a product category, or
input for a search bar.

This information will be incorporated into the query sent to the database so
that the appropriate information may  be retrieved and returned to the
application, which will then decide how to present it (product page, tables, etc
.).

## What is SQL Injection (SQLi)

There is a rule in Security; never trust user input. This rule is often
neglected or simply unknown, and is thus the root of many attacks. SQL Injection
is one such attack.

SQL Injection occurs when the user input is not properly sanitized before being
incorporated into a query. This allows the attacker to hijack control of the SQL
command sent to the database, allowing them to execute arbitrary commands.

Databases can contain user information, banking, product information (such as
their prices) amongst other things. When an attacker controls the
queries sent to a database they can potentially retrieve and or modify this
information.

There are three categories of SQLi:

* **Inband**: The most straightforward kind of attack; data is retrieved in the
same channel that is used to inject the SQL code. \[1].

* **Inferential**: There is no actual transfer of data, but the tester is able to
reconstruct the information by sending particular requests and observing the
resulting behavior. \[1] This attack is often called a Blind SQL Injection.

* **Out-of-band**: Data is retrieved using a different channel (e.g.: email) \[1]

These classes can then be broken down into various types of SQLi attacks,
based on the configuration of the server and the behavior of the application.
Roughly:

* **Error Based Attack**: An Inband technique relying on error messages for the
attacker to understand their target.

* **Union Based Attack**: An Inband technique relying on an SQL keyword to
combine multiple queries into one response.

* **Boolean Based Attack**: An Inferential technique relying on the application
behaving differently based on a boolean (TRUE or FALSE) query sent.

* **Time Based Attack**: Similar to a Boolean Based Attack. We ask the
database to wait a given amount of time before returning the results if TRUE.
What this means is if we send our information (example through a search bar) and
it takes longer for the application to respond, for example 10 seconds if we
asked the database to wait 10 seconds, we know the condition is true.

More detail will be given later on these attacks. If you can, watch the
conference given by Joe McCray at Defcon 17 \[1]. It is hands down one of the
best SQL Injection videos I have seen (and most entertaining as well).

## The Basics
Let's ignore the kinds of SQL injection for a few minutes and understand what
is actually going on.

Let's imagine a web application that displays, once you are logged in, your
email address. To retrieve your email address based on a username, we would
imagine a simple query as such:

```
SELECT email FROM people WHERE username LIKE ' + input + ' AND is_active = TRUE
```

This is asking the database for your email, which is stored in a database table
named *people* with a constraint that the account must be active (and not, for
example, banned).

To simplify things, let's imagine the username is provided in the URL. It would
look something like this:

```
http://www.vulnerableapp.example/account?user=kevo
```

As expected a username is provided, in this case *kevo*. Now this is how the
developer wants the users to use the application, perhaps this link is in a
button or clickable image. Cool.

Now what happens if I manually enter the following URL?

```
http://www.vulnerableapp.example/account?user=' or 'a' LIKE 'a
```

The query becomes:

```
SELECT email FROM people WHERE username LIKE '' OR 'a' LIKE 'a' AND is_active = TRUE
```

The SQL condition is valid, and effectively becomes:

```
SELECT email FROM people WHERE is_active = TRUE
```

The only thing limiting which emails should be provided is the
*is_active = TRUE*. This will return all active account emails.

Now what happens if I want everyone's email? Don't judge me, I'm greedy.

```
http://www.vulnerableapp.example/account?user=' or 'a' LIKE 'a'--
```

The query becomes:

```
SELECT password FROM people WHERE username LIKE '' or 'a' LIKE 'a'-- AND is_active = TRUE
```

Note the SQL comment delimiter **--**. This thus commented out the condition for
only active accounts. This query will now return everyone's email.

Now this example is obviously vulnerable and has more issues than just SQLi, but
it is simple enough that we can focus on the concept of SQLi. A more realistic
scenario would be using a Session Id (SID) passed through an HTTP Cookie, but
the attack remains the same. I can still modify that Cookie, replacing the SID
with SQL code, fulfilling my injection. In fact, aside from URLs and Cookies,
attacks can originate from any source of input that is coming from the client.

This is the essence of SQL Injection. Hijack the application's query to execute
your arbitrary commands. The issue is, we don't always have the query in front
of us nor do we usually know the structure of the database. This is where attack
techniques come into play.

## Types of attacks

### Error Based Attack

#### Category
Inband technique

#### Description
Error Based Attacks rely on error messages displayed by the server or
application to obtain information on the structure of the SQL query itself, the
database, and or the table.

These error messages are often used in the development of the application allowing
developers to quickly understand and debug their errors. It also simplifies an
attacker's goal of understanding the database.

#### Example
Let's assume we're getting product details from an online store. The typical URL
may look something like this:

```
http://www.vulnerableapp.example/product?id=42
```

When we try one of the most basic forms of testing for SQL Injection, adding
a quotation mark:

```
http://www.vulnerableapp.example/product?id=42'
```

We can see the injection attempt provides the following error:

```
Unclosed quotation mark after the character string ".
```

While this is useful in debugging our own SQL Injections, it can be taken one
step further and be used for SQL Enumeration, something I will cover in a later
post. For example, imagine the following query executed by a MSSQL Server:

```
http://www.vulnerableapp.example/product?id=42 or 1 in (SELECT user)--
```

The error message will be something like:

```
Conversion failed when converting the nvarchar value 'admin' to data type int.
```

The error message reveals our queries are being executed as user 'admin'.

As we can see, these error messages can clearly indicate column types, names or
configurations, simplifying the actual injection attempt as it is informing you
that you can inject, but even more so, it is holding your hand and telling you
what is wrong with the query or outputting database information directly.

### Union Based Attack

#### Category
Inband technique

#### Description
Union Based Attacks use the SQL keyword *UNION* to combine multiple SQL query
results into one response.

This will not have it's own error page but rather, the output will be seen in
the application. It could, for example, be used to build the page, a table in
the page, etc.

#### Example

Imagine the application has a table filled with database information which
it outputs. For example a table of products with their name and price such as:

```
http://www.vulnerableapp.example/product?product=home
```

| Name | Value |
| ---- | ------ |
| table | 20£ |
| lamp | 8£ |

A union based attack would try and inject another select statement, here
retrieving what is obviously 2 columns, filled with more useful information
such as the database version:

```
http://www.vulnerableapp.example/product?product=home' UNION ALL SELECT @@version, '1'--
```

Resulting in:

| Name | Value |
| ---- | ------ |
| table | 20£ |
| lamp | 8£ |
| 5.5.41-MariaDB | 1 |

The difficulty here is if the data types are not correct, it could result in an
empty table (the server had an error). To get around this you can use *null*
instead of a string or int value for extra columns.

### Boolean Based Attack

#### Category
Inferential technique

#### Description
Perhaps the SQL data is not revealed directly, but the application behaves
differently whether the SQL result is *TRUE* or *FALSE*. An example would be
that maybe the application returns a HTTP 404 or redirects to the home page if
the query is FALSE. Maybe just a custom error message which reveals no relevant
information.

Through this, we can see if a query is TRUE or FALSE, and by asking specific
questions such as *Is the user running the query as admin* or *is the database
version greater than x* we can enumerate the database.

As you can imagine this is relatively slow and tedious and could require many
queries to obtain database or table names.

#### Example
As demonstrated by OWASP \[3] let's suppose the URL is:

```
http://www.example.com/index.php?id=1
```

and the executed query is:

```
SELECT field1, field2, field3 FROM Users WHERE Id='$Id'
```

This can be easily exploited by adding a single quote, as we previously saw in
the section [The Basics](##The Basics).

Let's assume we want to retrieve the username for the account executing the
queries on the database, and let's assume it can be retrieved using the keyword
*username*.

We have three SQL functions that interest us:
* SUBSTRING(text, start length): retrieve *length* characters starting from the
*start* position of text *text*. Returns null otherwise.
* ASCII(char): returns the ascii numerical value of the character *char*

With these two functions we can start asking questions by appending it to the
WHERE, for example:

is the first character of the username an 'a' (ASCII 97):

```
http://www.example.com/index.php?id=1' AND ASCII(SUBSTRING(username,1,1))=97 AND 'a'='a
```

If the application behaved *normally* we know the first character of the
username is 'a'.

Using this technique we can enumerate over each character to eventually form
the username. As you can imagine, this requires a sizeable number of queries.

### Time Based Attack

#### Category
Inferential technique

#### Description
For a boolean based attack the application behaves differently. Now what happens
if none of that is the case? We find SQL Injection is possible, but the
application does not behave any differently nor does it display anything? Well,
we can make it behave differently.

This attack will ask the database to wait a certain amount of time if the query
is TRUE. Thus, the webpage will take longer to load as it waits for the response
from the database.

The period to wait must be long enough to ensure the time difference can not be
the cause of a slow network or high database load. As you can imagine if
thousands of queries need to be sent, this will take a significant amount of time.

#### Example
Let's take the Boolean example, but assume that there is no way of inferring a
difference (error message or change in application response).

We have the vulnerable URL:
```
http://www.example.com/index.php?id=1
```

We will assume the database is a MySQL 5.X.

We will use the same functions as in the boolean based attack, but add the
following:
* IF(condition, true_state, false_state): if the condition in *condition* is
TRUE, run the statement *true_state* else run the statement *false_state*
* sleep(sec): Pause execution for *sec* seconds.

Our new injection will then be the following:

```
http://www.example.com/index.php?id=1' AND IF(ASCII(SUBSTRING(username,1,1))=97, sleep(10), 'false')--
```

### Tips

#### Testing for SQL Injection
Imagine you have the following:

```
http://www.vulnerableapp.example/product?id=42
```

An effective means of testing for SQL injection, whether or not inferential
methods are later required for exploitation, would simply be testing if an
arithmetic expression is evaluated.

```
http://www.vulnerableapp.example/product?id=(41+1)
```

If the same product page is shown (that of id=42), congratulations, SQL
Injection is possible.

This is demonstrated by Joe McCray in \[1].

### Cheat Sheet
While SQL is a standardized language, databases handle data types and database
specific commands (such as retrieving the version, users, passwords, etc.)
differently. As such proper references, aka cheat sheets, are invaluable.

The best I've seen on the net come from Pentest Monkey \[4] who provides cheat
sheets for a variety of databases including MySQL, PostgreSQL, MSSQL, etc.

### Tools
Tools that automate SQL Injection are tricky. While they may support many kinds
of RDBMS and injection locations (URL, HTTP Header, Cookies, etc) they can be
loud and they can be spotted by an IDS/IPS with relative ease. They also aren't
100% effective, sometimes making manual injection necessary.

Take these for what they are. They are tools that should be used as a support
when applicable. Ensure you know how they work, when to use them, and what
can go wrong. Try not to be dependent on them.

* SQLMap \[5]
* SQLNinja \[6]
* BSQL \[7]
* TheMole \[8]


## References
1. DEFCON 17 - Joseph McCray - Advanced SQL Injection
https://www.youtube.com/watch?v=rdyQoUNeXSg
2. https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)#Boolean_Exploitation_Technique
3. https://www.owasp.org/index.php/SQL_Injection
4. http://pentestmonkey.net/cheat-sheet/sql-injection
5. https://github.com/sqlmapproject/sqlmap
6. http://sqlninja.sourceforge.net/
7. https://labs.portcullis.co.uk/tools/bsql-hacker/
8. https://sourceforge.net/projects/themole/
