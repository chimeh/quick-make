du -a |egrep "Makefile"| egrep "app/|box_spec/|header/|lib/|mk/" | awk '{print $2}' | while read i;do  perl -ni  -e' s@systems/linux/user/@app/linuxuser/@g;print '  $i;done

du -a |egrep "Makefile"| egrep "app/|box_spec/|header/|lib/|mk/" | awk '{print $2}' | while read i;do  perl -ni  -e' s@systems/linux/kernel/modules/@app/linuxkern/@g;print '  $i;done

}/make/

du -a |egrep "Makefile"| egrep "app/|box_spec/|header/|lib/|mk/" | awk '{print $2}' | while read i;do  perl -ni  -e' s@}/make/@}/mk/@g;print '  $i;done

du -a |egrep "Makefile"| egrep "app/|box_spec/|header/|lib/|mk/" | awk '{print $2}' | while read i;do  perl -ni  -e' s@}/include@}/header@g;print '  $i;done
