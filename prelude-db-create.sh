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

db_user="root"
db_password=""
db_name="prelude"

manager_password=""
manager_user="prelude"



ask_db_name () {
	echo
	echo -n "Enter the name of the Prelude database [${db_name}]: "
	read answer
	
	if [[ "${answer}" != "" && "${answer}" != "${db_name}" ]]; then
		db_name=${answer};
	fi
}


ask_db_user () {
	echo
	echo -n "What is the database administrative user ? [${db_user}]: "
	read answer

	if [[ "${answer}" != "" && "${answer}" != "${db_user}" ]]; then
		db_user = ${answer};
	fi

}



ask_manager_user() {
	echo
	echo "We need to create an user to be used by the Prelude Manager in order"
	echo "to access the \"${db_name}\" database."
 	echo

	echo -n "Username to create [prelude] : "
	read answer

	if [[ "${answer}" != "" && "${answer}" != "${manager_user}" ]]; then
		manager_user = ${answer};
	fi
}



ask_password () {
        echo -n "Please enter a password: "
	read -s answer
	echo

	echo -n "Please comfirm entered password: "
	read -s answerbis
	echo

	if [[ "${answer}" != "${answerbis}" ]]; then
	        echo
		echo "Password mismatch. Please try again"
		ask_password;
        else
                password=${answer}
	fi
}



db_confirm ()
{
	answer=""
	echo
	echo "Please confirm those information before processing" :
	echo
	echo "Database name	: ${db_name}"
	echo "Database admin user: ${db_user}"
	echo "Database admin password: (not shown)"
	echo
	echo "${db_name} owner user: ${manager_user}"
	echo "${db_name} owner password: (not shown)"
	echo
	echo -n "Is everything okay ? (yes/no) : "
	read answer
	

	case $answer in
		no) 
			echo "Restarting installation procedure."
			idmef
			exit
			;;

		yes)
			true
			;;

		*)
			db_confirm
			;;
	esac
}



db_create ()
{
	echo
	echo "Creating the database..."
	mysqladmin -u "${db_user}" --password="${db_password}" create "${db_name}"
}



db_create_users ()
{
        echo
        echo "Creating user \"${manager_user}\" for database \"${db_name}\", using \"${db_user}\" to connect to the database.";
        mysql -u ${db_user} --password=${db_password} -e "GRANT ALL PRIVILEGES ON ${db_name}.* TO ${manager_user}@localhost IDENTIFIED BY '${manager_password}';" ${db_name}

	echo
        echo "Creating tables with ./plugins/db/mysql/mysql.sql"
        mysql -u ${manager_user} --password=${manager_password} --database ${db_name} < ./plugins/db/mysql/mysql.sql

        echo
        echo "If everything succeed, you should now be able to launch prelude-manager with thoses parameters :"
        echo "prelude-manager --mysql --dbhost localhost --dbname ${db_name} --dbuser ${manager_user} --dbpass \"not shown\""
	echo
	echo "Or you may modify the prelude-manager configuration file to include theses informations"
}



idmef () {
	ask_db_name
	ask_db_user
	
	echo
        echo "We need the password of the admin user \"${db_user}\" to log on the database."
	ask_password
        db_password=${password}

	ask_manager_user
	echo
	echo "We need a password for the \"${manager_user}\" account."
	ask_password
	manager_password=${password};
	
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
