======================
NoWannaNoCry - nwnc.py
======================

A script to help mitigate against the WCry malware which was infecting
machines over the internet.  Note: The spreading of the initial version
of this malware seems to have been stopped by a built-in kill switch.

Some script operations need elevated permissions, so don't just trust me
on this, but read this document carefully and have a look at the code
itself before running it.

**Important:** The script can only diagnose and close the security hole
which is being exploited by WCry to infect new machines.  To my
knowledge, so far it's not possible to recover already encrypted files
without the encryption key (which of course I don't have).  Therefore,
this script won't help you if your machine is already infected.


Disclaimer / WIP
----------------

**This is a work in progress and as such is probably not (yet) suitable
to be run on mission critical systems.  Also there's no
guarantee/warranty of any kind, as pointed out in the LICENSE.**


Known Issues
~~~~~~~~~~~~

  * The ``fix`` command hasn't been implemented yet.

  * Has not been tested on many different systems yet, so it may not be
    robust enough to run on yours.


About WCry
----------

"WCry", "WannaCry", "WannaCrypt", "WanaCrypt0r", "Wanna" and some others
are all names for a malware/ransomware which has recently surfaced and
can spread rapidly.

In a nutshell, it can infect vulnerable Windows systems without any user
interaction.  Once infected, it will encrypt various types of files on
those systems, then prompt the user to pay ~300$ in Bitcoins for the
decryption key.

It does so by exploiting a critical Windows security hole using code
derived from the recently leaked trove of NSA hacking tools (`EternalBlue
<https://en.wikipedia.org/wiki/EternalBlue>`_).  From what I've read it's
not entirely clear how it's spreading (i.e. if exploiting that security
hole is the only means of propagation).

The bad news is that the security hole it exploits at least inside a
local network doesn't require any user interaction.  The good news is
that Microsoft has patched that hole in a recent security update (already
back in March).  So if your machines are up-to-date, they're probably not
vulnerable.

For further information read the following articles:

  * `An NSA-derived ransomware worm is shutting down computers
    worldwide - Ars Technica`__

  * `Player 3 Has Entered the Game: Say Hello to 'WannaCry' - Talos
    Blog`__

  * `PSA: Massive ransomware campaign (WCry) is currently being
    conducted. ... - reddit`__

__ https://arstechnica.com/security/2017/05/
   an-nsa-derived-ransomware-worm-is-shutting-down-computers-worldwide/
__ https://blogs.cisco.com/security/talos/wannacry
__ https://www.reddit.com/r/pcmasterrace/comments/6atu62/
   psa_massive_ransomware_campaign_wcry_is_currently/


About this script
-----------------

The script is actually nothing special, just runs a bunch of commands
which I gathered from the previously mentioned links (all credit goes to
the respective parties).  It's written in Python [1]_, which has to be
installed on your computer (see `Python`_ below).

The script accepts the following parameters:

  * ``-c`` or ``--check``: Check if the system is vulnerable.
    
  * ``-m`` or ``--mitigate``: Disable the SMB v1 protocol if no fix is
    already installed.

  * Soon to come, not yet done: ``-f`` or ``--fix``: ...


Usage
-----

Download the file *nwnc.py* from the *src* folder and open a command
prompt (e.g. press Windows key + R, then type: ``cmd``)::

    \> cd path\to\directory\containing\the\script
  
If you only want to see if your system is vulnerable::

    \> python nwnc.py -c

If you want to disable the SMB v1 protocol [2]_ in case your system is
vulnerable (``-m`` implies ``-c``)::

    \> python nwnc.py -m


Python
------

`Python <https://www.python.org/>`_ is a scripting language available for
all major platforms and needs to be installed on your system to run this
script.

If you don't want to do that, I recommend you have a look at the reddit
thread to which I linked in `About WCry`_ for manual instructions.


Additional Links
----------------

  * `Microsoft Security Bulletin MS17-010`_

  * Even more information: `<https://github.com/Hackstar7/WanaCry>`__

  * Fixes for older, unsupported Windows versions:
    `<https://arstechnica.com/security/2017/05/wcry-is-so-mean-microsoft
    -issues-patch-for-3-unsupported-windows-versions/>`__


.. _Microsoft Security Bulletin MS17-010:
   https://technet.microsoft.com/en-us/library/security/ms17-010.aspx


.. [1] In Python because I've yet to spend some time to properly learn
       PowerShell myself.  If someone wants to provide a script entirely
       written in PowerShell, feel free to send me a pull request or a
       link to your project/site.

.. [2] If you're curious as to why disabling the SMB v1 protocol
       mitigates the problem, check the Microsoft Security Bulletin in
       `Additional Links`_.
