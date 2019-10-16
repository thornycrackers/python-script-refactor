%title: Python Script Refactor
%author: Cody Hiar
%date: 2019-10-15

-> Python Script Refactor <-
============================

-------------------------------------------------

# About Me

* Graduated Computer Engineering at U of A
* Now working remotely @ Blendable
* Vim/Tmux Diehard, also cli in general
* Interests: Python, Automation, DevOps, Linux

# Where I be

* www.codyhiar.com
* www.github.com/thornycrackers

# Past Presentations (available on GitHub)

* Docker for Homo Troglodytes (YEGSEC)
* Scraping with scrapy (YEGSEC)
* Python Daemons (Edmonton.py)
* Setting Django up on a VPS (Edmonton.py)

-------------------------------------------------

-> My Goals <-
==============

* Give a quick rundown on tools
* Show some "cool" tricks
* Give a couple tips modularizing code to move past the single script.

-------------------------------------------------

-> Stop Calling it Bad Code <-
==============================

-> https://blog.pragmaticengineer.com/bad-code/ <-

-> Props to the brave soul who supplied the code <-

-------------------------------------------------

-> Automatic Formatting <-
==========================

```
pip3 install --user isort
pip3 install --user black
isort myscript.py
black myscript.py
```

Automatic linters in ANY language are always a great step towards learning how
to writing clean code. They also require little to no investment on your behalf.
Almost all modern language will have some sort of tool available.

-------------------------------------------------

-> Manual Formatting <-
=======================

```
pip3 install --user flake8
pip3 install --user flake8-bugbear
pip3 install --user flake8-docstrings
pip3 install --user flake8-isort
pip3 install --user pep8-naming
pip3 install --user pydocstyle
```

Flake8 existed before black and has LOTS of plugins to finely tune the rules
to your liking. Flake8 requires you to make manual changes but will help you in
making your scripts consistent during your refactors. `NOTE:` flake8 defaults to
80 line length where as black allows up to 88. To make sure they play nice together
you can create a `.flake8` file and update `max-line-length`. This repo has an
example.

-------------------------------------------------

-> Global Constants use Capitals and Tuples instead of list/set <-
==================================================================

```
APIURI = "https://lol.nope/redacted"
infra_client_ID = "ALSO-REDACT" 
userlist = { ... }
```

vs

```
APIURI = "https://lol.nope/redacted"
INFRA_CLIENT_ID = "ALSO-REDACT" 
USERLIST = ( ... )
```

Capital letters are a typical pattern in python to signify global static vars
(e.g `crypto.FILETYPE_PEM`). As your script grows other files can reference
global constants instead of magic numbers (crypto.FILETYPE_PEM == 1). Tuples
instead of lists means that code cannot modify your values. I like to put tuples
into a separate file called `constants.py` so the top of my file is cleaner

-------------------------------------------------

-> Loading key file into it's own function <-
=============================================

Instead of the file being loaded into the global namespace it can be loaded
when it is needed. Other scripts can also reuse this function if they need to
access that file. This will build onto a larger idea of writing for modularity.

-------------------------------------------------

-> Long Strings into Variables Before Function Calls <-
=======================================================

```
results = sniff(iface="enp10s0", prn=packet_handler, filter="...", store=0)
```

vs

```
filter="..."
results = sniff(iface="enp10s0", prn=packet_handler, filter=filter, store=0)
```

In the first example the end of the function call is pushed off the screen
whereas the second one we can see the entire call and most of the filter
variable. Other devs will appreciate not having to scroll just to read the
function being called.

-------------------------------------------------

-> Consider "not" logic to save on indents <-
=============================================

```
if pkt[2][1].Method == "POST":
    if getattr(pkt[2][1], "Content-Type") == "application/x-www-form-urlencoded":
        {code block}
```

vs


```
if pkt[2][1].Method != "POST":
    return
if getattr(pkt[2][1], "Content-Type") != "application/x-www-form-urlencoded":
    return
{code block}
```

If you have deeply nested code it can sometimes be more valuable to test for
the opposite of what you are looking for to save on deep indentations which
gives your code more room to breathe.

-------------------------------------------------

-> Use if/else vs except UnboundLocalError <-
=============================================

```
try:
    print(pass_rip)
except UnboundLocalError: #password not found in blob; bail
    logging.debug("password bail")
    break
```

vs

```
if not pass_rip:
    logging.debug("password bail")
    break
print(pass_rip)
```

We can use if statements to see if a variable exists instead of try/catch

-------------------------------------------------

-> itertools.product vs Double for loop <-
==========================================

```
for passw in passlist:
    if passw in splitified[1]:
        for userstr in userlist:
            if userstr in splitified[1]:
                {code block}
```

vs

```
password_and_users = itertools.product(passlist, userlist)
for passw, userstr in password_and_users:
    if passw in splitified[1] and userstr in splitified[1]:
        {code block}
```

`itertools.product` will compute the Cartesian product between to iterables so
we can avoid having nested for loops and checks.

-------------------------------------------------

-> Handling Multiple Exceptions <-
==================================

```
except IndexError:
    pass #for debug, remove or handle me
except AttributeError:
    pass #for debug, remove or handle me
except ConnectionError:
    logging.error("...")
```

vs

```
except (IndexError, AttributeError):
    pass
except ConnectionError:
    logging.error("...")
```

If we have multiple exceptions we can put them all on the same line. 

-------------------------------------------------

-> Using __name__ == '__main__' <-
==================================

```
mystr = "Hello"
print(mystr)
```

vs

```
def main():
    mystr = "Hello"
    print(mystr)
    
if __name__ == "__main__":
    main()
```

^

Using this little trick our `main` function is only file is called directly
from the command line but if another python script imports our file that code
will not be ran.

-------------------------------------------------

-> logger = logging.getLogger(__name__) <-
==========================================

```
logging.basicConfig(...)
logging.info(...)
```

vs

```
logging.basicConfig(...)
logger = logging.getLogger(__name__) <-
logger.info(...)
```

^

In this example we are letting the runtime name the logger for our file. This
is helpful to prevent namespace collisions but also makes the logger in each
file unique so that we can fine tune each logger to our specific needs. E.g:
mute noisey files, set the log level higher or lower, send to different
sources, adjust formatting.

-------------------------------------------------

-> Using a REPL for developing code <-
======================================

This is by far the best way to learn to getting hands on experience with code
that will be help you decide how to organize code. It will help expose weak
points and also aid in developing more modular code. If you do not want to use
a repl you can also just write a small script that imports and uses your code.
Some good REPLs: bpython, ipython, ptpython

-------------------------------------------------

-> Questions, comments, concerns? <-
====================================
