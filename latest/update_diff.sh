PACED_CHIRPING_URL="https://raw.githubusercontent.com/JoakimMisund/net-next/paced_chirping"
ORIG_URL="https://raw.githubusercontent.com/JoakimMisund/net-next/master"
OUTPUT_NAME="changes.diff"
echo "" > $OUTPUT_NAME

FILES=(include/linux/tcp.h  \
	   include/net/tcp.h \
	   net/ipv4/tcp_output.c \
	   net/ipv4/tcp_minisocks.c \
	   net/ipv4/tcp.c \
	   net/ipv4/sysctl_net_ipv4.c \
	   net/ipv4/tcp_input.c \
	   include/net/netns/ipv4.h)
for FILE_NAME in "${FILES[@]}"
do
    DIR=$(dirname "./net-next/$FILE_NAME")
    if [ ! -d $DIR ]; then
	mkdir -p $DIR
    fi

    wget "$PACED_CHIRPING_URL/$FILE_NAME" -O "$DIR/$(basename $FILE_NAME)"
    wget "$ORIG_URL/$FILE_NAME" -O "$DIR/$(basename $FILE_NAME).original"

    diff -uNr "$DIR/$(basename $FILE_NAME).original" "$DIR/$(basename $FILE_NAME)" >> $OUTPUT_NAME
done
