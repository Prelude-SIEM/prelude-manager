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

####
# Prelude IDMEF6 Database part

db_user="root"
db_password=""
db_name="prelude"

db_type="" # Type can be either mysql or pgsql

manager_password=""
manager_user="prelude"

warning () {
	answer=""
	clear
	echo
	echo "Prelude Database Support Installation"
	echo "====================================="
	echo
	echo "*** Phase 0/5 ***"
	echo
	echo "Warning: if you want to use database support with prelude"
	echo " You should dedicate the database for this job only."
	echo
	echo "So if you ever have a database running for another job"
	echo " please think about taking it away, because this script"
	echo " will install prelude as a dedicated database and you"
	echo " could meet some troubles with your old bases."
	echo
	echo "Do you want to install a dedicated database for prelude ?"
 	echo -n " (y)es / (n)o : "
	read answer
	case $answer in
	    y)
		echo
		;;
	    n)
	        echo
		echo "Installation aborted on user choice."
		echo
		exit
		;;
	    *)
		echo
		echo "Please read the warning message and choose y or n"
		read
		warning
	esac

}

ask_db_type () {
	answer=""
	echo
	echo "*** Phase 1/5 ***"
	echo
	echo -n "Enter the type of the database [mysql|pgsql]: "
	read answer
	
	if [[ "${answer}" == "mysql" || "${answer}" == "pgsql" ]]; then
		db_type=${answer}
	else
		ask_db_type
	fi
}

ask_db_name () {
	answer=""
	echo
	echo
	echo "*** Phase 2/5 ***"
	echo
	echo -n "Enter the name of the database that should be created to stock alerts [${db_name}]: "
	read answer
	
	if [[ "${answer}" != "" && "${answer}" != "${db_name}" ]]; then
		db_name=${answer}
	fi
}


ask_db_user () {
	answer=""
	case $db_type in
	    mysql)
		db_user="root"
		;;
	    pgsql)
		db_user="postgres"
		;;
	esac

	echo
	echo "*** Phase 3/5 ***"
	echo
	echo "This installation script has to connect to your ${db_type} database in order to create a user dedicated to stock prelude's alerts"
	echo -n "What is the database administrative user ? [${db_user}]: "
	read answer

	if [[ "${answer}" != "" && "${answer}" != "${db_user}" ]]; then
		db_user=${answer}
	fi

}



ask_manager_user() {
	answer=""
	echo "*** Phase 4/5 ***"
	echo
	echo "We need to create a database user account that will be used by the Prelude Manager in order to access the \"${db_name}\" database."
 	echo

	echo -n "Username to create [prelude] : "
	read answer

	if [[ "${answer}" != "" && "${answer}" != "${manager_user}" ]]; then
		manager_user=${answer}
	fi
}



ask_password () {
	answer=""
        echo -n "Please enter a password: "
	stty -echo
	read answer
	stty sane
	echo

	echo -n "Please comfirm entered password: "
	stty -echo
	read answerbis
	stty sane
	echo

	if [[ "${answer}" != "${answerbis}" ]]; then
	        echo
		echo "Password mismatch. Please try again"
		ask_password
        else
                password=${answer}
	fi
}



db_confirm ()
{
	answer=""
	echo
	echo "*** Phase 5/5 ***"
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
	echo "Creating the database ${db_name}..."
	case $db_type in
		mysql)
		    mysqladmin -u "${db_user}" --password="${db_password}" create "${db_name}"
		    ;;
		pgsql)
		    /etc/init.d/postgresql reload
		    su - "${db_user}" -c createdb "${db_name}"
		    ;;
		*)
		    echo "Weird error with the database type ${db_type}"
		    exit
		    ;;
	esac
}



db_create_users ()
{
	echo
       	echo "Creating user \"${manager_user}\" for database \"${db_name}\", using \"${db_user}\" to connect to the database.";

	case $db_type in

		mysql)
			mysql -u ${db_user} --password=${db_password} -e "GRANT ALL PRIVILEGES ON ${db_name}.* TO ${manager_user}@localhost IDENTIFIED BY '${manager_password}';" ${db_name}

			echo
			echo "Creating tables with ./plugins/db/mysql/mysql.sql"
			mysql -u ${manager_user} --password=${manager_password} --database ${db_name} < ./plugins/db/mysql/mysql.sql

			;;
		pgsql)
			(grep prelude-ids_frontend /etc/postgresql/pg_hba.conf ; echo local all ident postgres ) > /etc/postgresql/pg_hba.conf_temp_prelude
			mv -f /etc/postgresql/pg_hba.conf_temp_prelude /etc/postgresql/pg_hba.conf
			(echo postgres root postgres; echo postgres root prelude) > /etc/postgresql/pg_ident.conf
			rm -rf /var/lib/postgres/data/prelude-ids_manager
			touch /var/lib/postgres/data/prelude-ids_manager
			(echo "${manager_user}"; echo "${manager_password}"; echo "${manager_password}") | /usr/lib/postgresql/bin/pg_passwd /var/lib/postgres/data/prelude-ids_manager 1>/dev/null
			/etc/init.d/postgresql reload

			psql -U ${db_user} -d template1 -c "CREATE USER ${manager_user} WITH ENCRYPTED PASSWORD '${manager_password}' NOCREATEDB NOCREATEUSER;"
			echo
			echo "Creating tables with ./plugins/db/pgsql/postgres.sql"
			psql -d "${db_name}" -U "${manager_user}" < ./plugins/db/pgsql/postgres.sql

			(grep prelude-ids_frontend /etc/postgresql/pg_hba.conf ; echo local ${db_name} password prelude-ids_manager ; echo host ${db_name} 127.0.0.1 255.0.0.0 password prelude-ids_manager ; echo local template1 ident postgres ) > /etc/postgresql/pg_hba.conf_temp_prelude
			mv -f /etc/postgresql/pg_hba.conf_temp_prelude /etc/postgresql/pg_hba.conf
			rm -rf /etc/postgresql/pg_ident.conf
			/etc/init.d/postgresql reload
			;;
		*)
			echo "Weird error with the database type ${db_type}"
			exit
			;;
		esac
       	echo   
	echo "-------------- End of Database Support Installation -------------"
	echo "If it succeeded, you should now be able to launch prelude-manager like that :"
	echo "==>  prelude-manager --${db_type} --dbhost localhost --dbname ${db_name} --dbuser ${manager_user} --dbpass xxxxxx"
	echo
	echo "Or you may modify the prelude-manager configuration file (/usr/local/etc/prelude-manager/prelude-manager.conf by default) in order to launch prelude-manager without database arguments:"
	echo "---------- cut here --->"
	case $db_type in
		mysql)
		    echo "[MySQL]"
		    ;;
		pgsql)
		    echo "[PgSQL]"
		    ;;
		*)
		    exit
		    ;;
	esac
	echo "# Host the database is listening on."
        echo "dbhost = localhost;"
	echo "# Name of the database."
	echo "dbname = ${db_name};"
	echo "# Username to be used to connect the database."
	echo "dbuser = ${manager_user};"
	echo "# Password used to connect the database."
	echo "dbpass = xxxxxx;"
	echo "<--- cut here ----------"
	echo 
	echo "Replace xxxxxx by the password you choose for the manager account"
	echo "-----------------------------------------------------------------"
}



idmef () {
	warning
	ask_db_type
	ask_db_name
	ask_db_user
	
	echo

	if [ "${db_type}" == "mysql" ]; then
	    echo "We need the password of the admin user \"${db_user}\" to log on the database."
	    if [ "${db_user}" == "root" ]; then
	    	echo "By default under ${db_type}, root has an empty password.."
	    fi
	    ask_password
	    db_password=${password}
	fi

	echo
	ask_manager_user
	echo
	echo "We need to set a password for this special \"${manager_user}\" account."
	echo "This password will have to be used by prelude-manager to access the database."
	ask_password
	manager_password=${password}
	
        db_confirm
	db_create
	db_create_users
}

idmef


# End of the IDMEF6 Database part
####


