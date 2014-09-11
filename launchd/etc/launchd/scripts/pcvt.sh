#!/bin/sh -
#
# Removed dependency from /etc/rc.

pcvt_precmd()
{
	if [ -x /usr/sbin/ispcvt ]; then
		/usr/sbin/ispcvt -d /dev/ttyv0 && return 0
	fi
	return 1
}

pcvt_echo()
{
	echo $1 "$2"
}

pcvt_start()
{
	# path for pcvt's EGA/VGA download fonts
	FONTP=/usr/share/misc/pcvtfonts

	echo "Configuring pcvt console driver:"

	# video adapter type

	adapter=`/usr/sbin/scon -d /dev/ttyv0 -a`

	pcvt_echo "-n" "  video adapter type is $adapter, "

	# monitor type (mono/color)

	monitor=`/usr/sbin/scon -d /dev/ttyv0 -m`

	pcvt_echo "" "monitor type is $monitor"

	# load fonts into VGA

	if [ $adapter = VGA ]; then
		pcvt_echo "-n" "  loading fonts: 8x16:0,"
		loadfont -d /dev/ttyv0 -c0 -f $FONTP/vt220l.816

		pcvt_echo "-n" "1 "
		loadfont -d /dev/ttyv0 -c1 -f $FONTP/vt220h.816

		pcvt_echo "-n" " 8x14:0,"
		loadfont -d /dev/ttyv0 -c2 -f $FONTP/vt220l.814

		pcvt_echo "-n" "1 "
		loadfont -d /dev/ttyv0 -c3 -f $FONTP/vt220h.814

		pcvt_echo "-n" " 8x10:0,"
		loadfont -d /dev/ttyv0 -c4 -f $FONTP/vt220l.810

		pcvt_echo "-n" "1 "
		loadfont -d /dev/ttyv0 -c5 -f $FONTP/vt220h.810

		pcvt_echo "-n" " 8x8:0,"
		loadfont -d /dev/ttyv0 -c6 -f $FONTP/vt220l.808

		pcvt_echo "" "1 "
		loadfont -d /dev/ttyv0 -c7 -f $FONTP/vt220h.808

	# setting screen sizes

		case ${pcvt_lines} in
		28)
			size=-s28
			pcvt_echo "" "  switching to 28 lines"
			;;
		40)
			size=-s40
			pcvt_echo "" "  switching to 40 lines"
			;;
		50)
			size=-s50
			pcvt_echo "" "  switching to 50 lines"
			;;
		*)
			size=-s25
			pcvt_echo "" "  switching to 25 lines"
			;;
		esac
	fi

	# use HP extensions to VT220 or plain VT220 ?

#	if checkyesno pcvt_hpext; then
#		emulation=-H
#		pcvt_echo "" "  setting emulation to VT220 with HP extensions"
#	else
		emulation=-V
		pcvt_echo "" "  setting emulation to VT220"
#	fi

	# for all screens do

	for device in /dev/ttyv*
	do
		# set emulation

		/usr/sbin/scon -d$device $size $emulation >/dev/null 2>&1
		if [ $? != 0 ]; then
			break 1
		fi

		# set cursor shape

		case ${pcvt_cursorh} in
		[Nn][Oo] | '')
			;;
		*)
			case ${pcvt_cursorl} in
			[Nn][Oo] | '')
				;;
			*)
				/usr/sbin/cursor -d$device -s$pcvt_cursorh -e$pcvt_cursorl
				;;
			esac
			;;
		esac

		# on monochrome monitor, set color palette to use a higher intensity

#		if checkyesno pcvt_monohigh && \
#			[ $monitor = MONO -a $adapter = VGA ]
#		then
			/usr/sbin/scon -d$device -p8,60,60,60
#		fi
	done

	# switch to screen 0

	pcvt_echo "" "  switching to screen 0"

	/usr/sbin/scon -d /dev/ttyv0

	# screensaver timeout

	case ${pcvt_blanktime} in
	[Nn][Oo] | '')
		;;
	*)
		pcvt_echo "" "  setting screensaver timeout to $pcvt_blanktime seconds"
		/usr/sbin/scon -d /dev/ttyv0 -t$pcvt_blanktime
		;;
	esac

	# national keyboard layout

	case ${pcvt_keymap} in
	[Nn][Oo] | '')
		;;
	*)
		pcvt_echo "" "  switching national keyboard layout to $pcvt_keymap"
		/usr/sbin/kcon -m $pcvt_keymap
		;;
	esac

	# keyboard repeat delay value

	case ${pcvt_keydel} in
	[Nn][Oo] | '')
		;;
	*)
		pcvt_echo "" "  setting keyboard delay to $pcvt_keydel"
		/usr/sbin/kcon -d$pcvt_keydel
		;;
	esac

	# keyboard repeat rate value

	case ${pcvt_keyrate} in
	[Nn][Oo] | '')
		;;
	*)
		pcvt_echo "" "  setting keyboard repeat rate to $pcvt_keyrate"
		/usr/sbin/kcon -r$pcvt_keyrate
		;;
	esac

	# done

#	if checkyesno pcvt_verbose; then
		echo "Finished configuring pcvt console driver."
#	else
#		echo "."
#	fi
}

# start here
# used to emulate "requires/provide" functionality
pidfile="/var/run/pcvt.pid"
touch $pidfile
pcvt_precmd
pcvt_start
exit 0
