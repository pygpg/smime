Python module and tools for constructing and sending PGP/MIME email.

The ``pgp_mime`` module makes it easy to construct and dispatch signed
and/or encrypted email using PGP_ and :RFC:`3156`.  It uses GnuPG_
(via `gpgme-tool`_) to perform the cryptography.

Installation
============

Packages
--------

Gentoo
~~~~~~

I've packaged ``pgp-mime`` for Gentoo_.  You need layman_ and
my `wtk overlay`_.  Install with::

  # emerge -av app-portage/layman
  # layman --add wtk
  # emerge -av dev-python/pgp-mime

Dependencies
------------

``pgp-mime`` is a simple package with no external dependencies outside
the Python 3 standard library.  There are a number of GnuPG_ wrappers
for python `out there`__, but none of them seem mature/stable enough
to be worth installing.  Instead, we use the `pyassuan`_ module to
talk to `gpgme-tool`_ over pipes or sockets.  If this isn't working
for you, you need only replace the ``pgp_mime.crypt`` module to handle
the cryptography.

__ wrappers_

Installing by hand
------------------

``pgp-mime`` is available as a Git_ repository::

  $ git clone git://tremily.us/pgp-mime.git

See the homepage_ for details.  To install the checkout, run the
standard::

  $ python setup.py install

Usage
=====

Pgp-mime has grown up as I've become more experienced with Python.
The current interface is much simpler, and there are lots of
docstrings showing you how to use each function.

If you're looking for a higher level example, pgp-mime includes a
command line script ``send-pgp-mime.py`` that allows you to send
signed and/or encrypted email from the command line.  I recommend you
use ``gpg2`` with my `wrappers and pinentry program`_ to allow easy
pinentry from the command line.  Here's how you could mail signed
grades to your class::

  $ FROM="From: Rincewind <rincewind@uu.edu>"
  $ head -n2 grades
  Twoflower <tf@isa.ae.cw>|9
  Eric Thursley <et@pseudopolis.net>|10
  $ while read LINE; do
      STUDENT=$(echo "$LINE" | cut -d '|' -f 1)
      GRADE=$(echo "$LINE" | cut -d '|' -f 2)
      HEAD=$(echo -e "$FROM\nTo: $STUDENT\nSubject: Grades")
      BODY=$(echo -e "$STUDENT,\n\nYou got a $GRADE.\n\nGood job.")
      send-pgp-mime.py -H <(echo "$HEAD") -B <(echo "$BODY") --mode sign
    done < grades

If you can convince your students to get PGP keys, you could also
encrypt their grades by changing ``--mode sign`` to ``--mode
sign-encrypt``.

Of course, if you're interested in working with students and grades,
you might also be interested in my `pygrader`_ package, which uses
pgp-mime under the hood.

Configuring the SMTP connection
-------------------------------

Pgp-mime supports two methods for sending messages (via
``pgp_mime.mail``).  It can either call your system's ``sendmail``
equivalent, or connect directly to an SMTP_ server using ``smtplib``.
Since I imagine SMTP will be more common, you can easily configure
your SMTP connection via ``~/.config/smtplib.conf``::

  [smtp]
  host: smtp.mail.uu.edu
  port: 587
  starttls: yes
  username: rincewind
  password: 7ugg@g3

All of these fields are optional.  ``host`` defaults to ``localhost``
and ``port`` defaults to 25.  If ``username`` is not given, we do not
attempt to login to the SMTP server after connecting.

If ``starttls`` is ``no`` or not given, the SMTP transaction occurs in
plain text (although the underlying emails will still be encrypted).
However, if you set a ``username`` (to login), pgp-mime will require a
STARTTLS_ to protect your password from sniffing.

Testing
=======

Run the internal unit tests using nose_::

  $ nosetests --with-doctest --doctest-tests pgp_mime

If a Python-3-version of ``nosetests`` is not the default on your
system, you may need to try something like::

  $ nosetests-3.2 --with-doctest --doctest-tests pgp_mime

Licence
=======

This project is distributed under the `GNU General Public License
Version 3`_ or greater.

Author
======

W. Trevor King
wking@tremily.us

.. _PGP: http://en.wikipedia.org/wiki/Pretty_Good_Privacy
.. _Gentoo: http://www.gentoo.org/
.. _layman: http://layman.sourceforge.net/
.. _wtk overlay: http://blog.tremily.us/posts/Gentoo_overlay/
.. _wrappers: http://wiki.python.org/moin/GnuPrivacyGuard
.. _pyassuan: http://blog.tremily.us/posts/pyassuan/
.. _gpgme-tool:
  http://git.gnupg.org/cgi-bin/gitweb.cgi?p=gpgme.git;a=blob;f=src/gpgme-tool.c;hb=HEAD
.. _Git: http://git-scm.com/
.. _homepage: http://blog.tremily.us/posts/pgp-mime/
.. _wrappers and pinentry program: http://blog.tremily.us/posts/gpg-agent/
.. _pygrader: http://blog.tremily.us/posts/pygrader/
.. _SMTP: http://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol
.. _STARTTLS: http://en.wikipedia.org/wiki/STARTTLS
.. _GnuPG: http://www.gnupg.org/
.. _nose: http://readthedocs.org/docs/nose/en/latest/
.. _GNU General Public License Version 3: http://www.gnu.org/licenses/gpl.html
