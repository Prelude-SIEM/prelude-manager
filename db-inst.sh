#!/bin/sh
#####
#
# Copyright (C) 2002 Laurent Oudot <oudot.laurent@wanadoo.fr>
# All Rights Reserved
#
# This file is part of the Prelude program.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by 
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
#
#####

# This is a script that aims at creating needed databases by the prelude project during the installation process.
# At this time this is just a test version that moreover only work for mysql...
# It will contain at least two parts :
# 1) Creation of IDMEFv6 Database
# 2) Creation of the Frontend Database (used in prelude-php-frontend)


####
# Prelude IDMEF6 Database part

name="prelude_idmef6"
user="root"
password=""
manager="prelude_manager"
manager_password=""

db_name () {
	answer=""
	echo -n Do you need to change the default name \(prelude_idmef6\) of the prelude IDMEF database ? [y/N]  
	read -n 1 answer
	echo 
	case $answer in
		y)      echo -n Ok. Give the new name of the prelude IDMEF database:  
	   		read name
			;;
		*) 
			;;
	esac
}

db_user () {

	answer=""
	echo -n Please give an admin user name to access the database in order for this current script to be able to connect to the database, and create needed stuff in next steps [root]:  
	read answer
	echo 
	case $answer in
		"") 
			echo Default \"root\" account will be used
			;;
		*)
			echo Specified \"$answer\" account will be used
			user=$answer
			;;
	esac
}

db_password () 
{
	answer=""
	answerbis=""
	echo -n Please give the password of the admin user $user to log on the database []:  
	read -s answer
	echo
	read -s -p Confirm: answerbis
	echo 
	case $answer in
		"") 
			echo Default empty password will be used \(note you should modify it\)
			;;
		*)
			if [ $answer == $answerbis ]; then
				echo Specified password will be used
				password=$answer
			else
				echo Passwords entered mismatched...
				db_password
			fi
			;;
	esac
}

db_confirm ()
{
	answer=""
	echo
	echo Please confirm those information before going on :
	echo
	echo Database name	: $name
	echo Database admin user: $user
	echo Database admin pswd: \(not shown\)
	echo
	echo -n Do you agree ? \(yes/no\)
	read -n 3 answer
	case $answer in
		yes)
			true
			;;
		no)
			echo Ok. We have to get back to the beginning.
			idmef
			;;
		*)
			db_confirm
			;;
	esac
}

db_create ()
{
	echo
	echo Creating the database...
	mysqladmin -u $user --password=$password create $name
}

db_create_users ()
{
	echo
	echo We need to create users on the database in order to update or to read them
	
	answer=""
	echo -n Do you need to change the name of the default account \"$manager\" for this on the database ? [y/N]:  
	read -n 1 answer
	echo 
	case $answer in
		y) 
			echo -n Please type the name of this account:
			read $manager
			;;
		*)
			;;
	esac
	
	echo The database account named $manager need also a password. Please choose one \(this couple manager/password will be used by prelude-manager to connect to the database in order to feed it with alerts...\).
	echo Dont forget this password...
	answer=""
	answerbis=""
	read -s -p Password: answer
	echo
	read -s -p Confirm: answerbis
	if [ $answer = $answerbis ]; then
		manager_password=$answer
		echo
		echo Ok. Creating $manager on $name, by using $user to connect to the database.
		mysql -u $user --password=$password -e "GRANT ALL PRIVILEGES ON $name.* TO $manager@localhost IDENTIFIED BY '$manager_password';" $name
		echo If there was no error then you will be able to launche prelude-manager with those parameters :
		echo prelude-manager --mysql -d localhost -n $name -u $manager -p $manager_password
		echo
		echo Creating tables with ./plugins/db/mysql/mysql.sql
		mysql -u $manager --password=$manager_password --database $name < ./plugins/db/mysql/mysql.sql
		echo done.
		echo
	else
		echo Passwords mismatched.
		echo Retrying the creation of a database user
		db_create_users
	fi
}

idmef () {
	db_name
	db_user
	db_password
	db_confirm
	db_create
	db_create_users
}

idmef


# End of the IDMEF6 Database part
####

####
# Frontend Database part

# End of the Frontend Database part
####