SQLassie
========

SQLassie is a database firewall that detects and prevents SQL injection attacks at runtime.

Usage
-----

SQLassie currently only supports MySQL. To start SQLassie, you'll need to configure how SQLassie connects to the MySQL server, start SQLassie listening on a different port that is now protected, and then configure your applications to connect through this alternate port instead of directly to MySQL.

As an example, consider a scenario where you have a MySQL database engine running and listening for connections on the domain socket `/var/run/mysql/mysqld.sock` and are running a MediaWiki installation.

First, start SQLassie using

    ./sqlassie -s /var/run/mysql/mysqld.sock -l 3307

Then, edit MediaWiki's configuration file `LocalSettings.php` connect to port 3307.

    $wgDBServer = "127.0.0.1:3307"

Note that you can't use localhost here; by default, MySQL interprets `localhost` as a request to use the direct database domain socket connection, and most web applications behave this way as well. Therefore, you have to use the explicit string `127.0.0.1` in order to force connections to go through the TCP port. Check your application's documentation for more information.

Testing
-------

Now that you've gotten everything up and running, check to see if your web application still loads. If it does, you can check to see if SQLassie is correctly filtering attacks against your database. Bring up a terminal and run

    mysql -u <user> -p -h 127.0.0.1 -P 3307 -C

to connect to the database through SQLassie.

We can run a number of tests here. First, SQLassie will block most error messages that are produced by MySQL, because this information can be valuable to hackers. Start by running

    SELECT * FROM foo;

Normally, MYSQL would respond with an error about no database being selected, but SQLassie intercepts the query and instead responds with `Empty set`. In this case, SQLassie recognized that the query was a `SELECT` query, and rather than give an error, it simply provided a response that made sense based on the query type.

Next, try running

    SELECT first_name, last_name, age FROM user WHERE id = 1323 UNION SELECT User, Password, 1 FROM mysql.user;

SQLassie identifies this query as containing a schema discovery attack and blocks the query, responding with a fake empty `Empty set` message.

Compiling
---------

SQLassie comes with two Makefiles: one meant for use with gcc, and one meant for use with clang++. Support for gcc is more thorough at this time, so to start building, link to the gcc Makefile by running

    ln -s Makefile.gcc Makefile

Next, you'll need to install some dependencies. On a Debian-based system, you should get everything you need by running

    apt-get install make g++ bison flex libboost-regex-dev libboost-thread-dev libboost-program-options-dev libboost-test-dev libboost-filesystem-dev libmysqlclient-dev

Finally, compile by running

    make
