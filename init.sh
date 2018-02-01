#!/bin/bash

FirstMenu()
{
  OPTION=$(dialog --title "Initial Configuration" --menu "Choose your option" 15 60 5 \
  "1" "Configure Network" \
  "2" "Set Hostname" \
  "3" "Change password" \
  "4" "Set Group/User" \
  "5" "Configure LVM"   3>&1 1>&2 2>&3)
}

ConfigNetwork()
{
    NetBrief
    n=$(/sbin/ip addr show up | grep ': ' | awk -F: '/eth/{print $2}' | wc -l)
    i=$(dialog --title "Configure Network" --inputbox "please input the interface number eth(0-$[n-1]) need to be configured:"  10 60 3>&1 1>&2 2>&3)
    result=$?
    if [ $result -eq 1 ] || [ $result -eq 255 ] ;then
       Status=1
    elif [ ! $i ] ;then
       dialog --title "Configure Network" --ok-label exit --msgbox "It can't be NULL,please configure again!" 15 60
       Status=1
    else
      dialog --title "Configure interface eth$i" --form "Please input the infomation of eth$i:" 15 60 6  \
      "IP address:" 1  1 "" 1  18  30  0  \
      "NETMASK:" 2  1 "" 2  18  30  0  \
      "GATEWAY(options):" 3  1 "" 3  18  30  0  \
      "DNS1(options):" 4  1 "" 4  18  30  0  \
      "DNS2(options):" 5  1 "" 5  18  30  0  \
      "Domain(options):" 6  1 "" 6  18  30  0  2>/tmp/.tmp
     
       IPADDR=$(awk 'NR==1{print}' /tmp/.tmp) 
       MASK=$(awk 'NR==2{print}' /tmp/.tmp) 
       GATEWAY=$(awk 'NR==3{print}' /tmp/.tmp) 
       DNS1=$(awk 'NR==4{print}' /tmp/.tmp)
       DNS2=$(awk 'NR==5{print}' /tmp/.tmp)
       Domain=$(awk 'NR==6{print}' /tmp/.tmp)
       HWADDR=$(/sbin/ip addr show eth$i | grep 'link/ether' | awk '{print $2}')  
    
       CheckIP
    fi
}
  
CheckIP()
{  
    if [ ! $IPADDR ] || [ ! $MASK ] ;then
      dialog --title "Configure interface eth$i" --ok-label exit --msgbox "IP & MASK can't be NULL,please configure again!" 15 60 
      Status=1
    else
      echo $IPADDR | grep "^[0-9]\{1,3\}\.\([0-9]\{1,3\}\.\)\{2\}[0-9]\{1,3\}$" > /dev/null;
        a=$(echo $IPADDR|awk -F . '{print $1}')  
        b=$(echo $IPADDR|awk -F . '{print $2}') 
        c=$(echo $IPADDR|awk -F . '{print $3}') 
        d=$(echo $IPADDR|awk -F . '{print $4}') 
        if [ $a -le 255 -a $b -le 255 -a $c -le 255 -a $d -le 255 ];then
cat >/etc/sysconfig/network-scripts/ifcfg-eth$i <<EOF
TYPE=Ethernet
DEVICE=eth$i
NAME=eth$i
BOOTPROTO=static
ONBOOT=yes
HWADDR=$HWADDR
IPADDR=$IPADDR
NETMASK=$MASK
GATEWAY=$GATEWAY
DNS1=$DNS1
DNS2=$DNS2
DOMAIN=$Domain
EOF
            find /etc/sysconfig/network-script -name 'ifcfg-eno*' -exec rm {} \; > /dev/null 2>&1
            find /etc/sysconfig/network-script -name 'ifcfg-ens*' -exec rm {} \; > /dev/null 2>&1
            find /etc/sysconfig/network-script -name 'ifcfg-em*' -exec rm {} \; > /dev/null 2>&1                        
            systemctl restart network.service > /dev/null 2>&1
            Status=1
        else
            dialog --title "Configure interface eth$i" --ok-label exit --msgbox "IP format error,Please enter the IP again." 15 60
            Status=1
        fi       
    fi
}    

Intbrief()
{
  x=$(/sbin/ip addr show up | grep ': ' | awk -F: '{print $2}' | wc -l)
  printf "%-13s%-25s%-20s%-23s%s\n" interface IP/MASK gateway  broadcast MAC > /tmp/.output
  printf "$(/sbin/ip addr show | grep ': ' | awk -F: '{print $2}' |sort)\n" > /tmp/.tmp
  while read line
  do
    DEV=$(echo $line)
    IPADDR=$(/sbin/ip addr show $DEV | grep "inet " | awk '{print $2}')
      if [ ! $IPADDR ];then
        IPADDR="unconfiged"
      fi
    GATEWAY=$(/sbin/route -n | grep "^0.0.0.0"| grep $DEV | awk '{print $2}')
      if [ ! $GATEWAY ];then
        GATEWAY="unconfiged"
      fi
    BROADCAST=$(/sbin/ip addr show $DEV | grep "brd" | awk '!/:/{print $4}')
      if [ ! $BROADCAST ];then
        BROADCAST="unconfiged"
      fi    
    MAC=$(/sbin/ip addr show $DEV | grep 'link/ether' | awk '{print $2}')
    printf "%-13s%-25s%-20s%-23s%s\n" $DEV $IPADDR $GATEWAY $BROADCAST $MAC  >> /tmp/.output
  done < /tmp/.tmp
}

InterBrief()
{
   Intbrief
   dialog --title "Show interface brief" --textbox  /tmp/.output  15 120  
}

NetBrief()
{
   Intbrief 
   dialog --title "Display Network Information" --exit-label Continue --textbox  /tmp/.output  15 120  
}

Hostname()
{
  HOSTNAME=$(dialog --title "Configure Hostname" --inputbox "Please input the Hostname:" 15 60 3>&1 1>&2 2>&3)
  result=$?
  if [ $result -eq 1 ] || [ $result -eq 255 ] ;then
      Status=0
  elif [ ! $HOSTNAME ] ;then
      dialog --title "Configure Hostname" --ok-label exit --msgbox "It can't be NULL,please configure again!" 15 60
      Status=0    
  else
      echo $HOSTNAME > /etc/hostname 
      dialog --title "Configure Hostname" --ok-label exit --msgbox "It will be effective after reboot." 15 60
      Status=0
  fi
}

UserPass()
{
   dialog --title "Change Password" --form "Please input the username and new password:" 15 60 2  \
   "Username:" 1  1 "" 1  18  30  0  \
   "Password:" 2  1 "" 2  18  30  0    2>/tmp/.tmp
   result=$?
   if [ $result -eq 1 ] || [ $result -eq 255 ] ;then
       Status=0
   else
       Username=$(awk 'NR==1{print}' /tmp/.tmp) 
       Password=$(awk 'NR==2{print}' /tmp/.tmp) 
       if [ ! $Username ] || [ ! $Password ];then
          dialog --title "Change Password" --ok-label exit --msgbox "Username & Password can't be NULL,please configure again!" 15 60 
          Status=0
       else
          echo $Password | passwd --stdin $Username > /tmp/.tmp 2>&1
          dialog --title "Change Password" --textbox  /tmp/.tmp  20 80 
          Status=0
       fi
   fi
}

GroupAdd()
{
   dialog --title "Add group/user" --form "Please input the infomation of a new user:" 15 60 3  \
   "Group:" 1  1 "" 1  18  30  0  \
   "Username:" 2  1 "" 2  18  30  0  \
   "Password:" 3  1 "" 3  18  30  0    2>/tmp/.tmp
   result=$?
   if [ $result -eq 1 ] || [ $result -eq 255 ] ;then
       Status=2
   else
       Group=$(awk 'NR==1{print}' /tmp/.tmp) 
       Username=$(awk 'NR==2{print}' /tmp/.tmp) 
       Password=$(awk 'NR==3{print}' /tmp/.tmp) 
       if [ ! $Group ] || [ ! $Username ] || [ ! $Password ];then
          dialog --title "Add group/user" --ok-label exit --msgbox "Group & Username & Password can't be NULL,please configure again!" 15 60 
          Status=2
       else
          groupadd $Group
          useradd -d /usr/$Username -g $Group -m $Username
          echo $Password | passwd --stdin $Username  > /dev/null 2>&1
          Status=2
       fi
   fi
}

UserAdd()
{
   dialog --title "Add user" --form "Please input the infomation of a new user:" 15 60 3  \
   "Username:" 1  1 "" 1  18  30  0  \
   "Password:" 2  1 "" 2  18  30  0    2>/tmp/.tmp
   result=$?
   if [ $result -eq 1 ] || [ $result -eq 255 ] ;then
       Status=2
   else 
       Username=$(awk 'NR==1{print}' /tmp/.tmp) 
       Password=$(awk 'NR==2{print}' /tmp/.tmp) 
       if [ ! $Username ] || [ ! $Password ];then
          dialog --title "Add user" --ok-label exit --msgbox "Username & Password can't be NULL,please configure again!" 15 60 
          Status=2 
       else
          useradd -d /usr/$Username -m $Username
          echo $Password |passwd --stdin $Username  > /dev/null 2>&1
          Status=2
       fi
   fi
}

UserMod()
{
   dialog --title "Change User group" --form "Please input the infomation of a user existing:" 15 60 3  \
   "Groupname :" 1  1 "" 1  18  30  0  \
   "Username:" 2  1 "" 2  18  30  0    2>/tmp/.tmp
   result=$?
   if [ $result -eq 1 ] || [ $result -eq 255 ] ;then
       Status=2
   else 
       group=$(awk 'NR==1{print}' /tmp/.tmp) 
       username=$(awk 'NR==2{print}' /tmp/.tmp) 
       if [ ! $username ] || [ ! $group ];then
          dialog --title "Change User group" --ok-label exit --msgbox "Groupname & Username can't be NULL,please configure again!" 15 60 
          Status=2 
       else
          usermod -g $group $username  2> /tmp/.tmp
          if [ `cat /tmp/.tmp | wc -l` -gt 0 ] ;then
             dialog --title "Change User group" --textbox  /tmp/.tmp  20 80           
             Status=2
          else
             Status=2      
          fi
       fi
   fi
}

UserDel()
{
      username=$(dialog --title "Delete User" --inputbox "Please input the Username need to be deleted:" 15 60 3>&1 1>&2 2>&3)
      result=$?
      if [ $result -eq 1 ] || [ $result -eq 255 ] ;then
          Status=2
      elif [ ! $username ] ;then
          dialog --title "Delete User" --ok-label exit --msgbox "It can't be NULL,please configure again!" 15 60
          Status=2    
      else
          userdel $username  > /tmp/.tmp 2>&1
          if [ `cat /tmp/.tmp | wc -l` -gt 0 ] ;then
             dialog --title "Delete User" --textbox  /tmp/.tmp  20 80           
             Status=2
          else
             Status=2      
          fi
      fi
}

GroupDel()
{
     group=$(dialog --title "Delete Group" --inputbox "Please input the Groupname need to be deleted:" 15 60 3>&1 1>&2 2>&3)
     result=$?
     if [ $result -eq 1 ] || [ $result -eq 255 ] ;then
         Status=2
     elif [ ! $group ] ;then
         dialog --title "Delete Group" --ok-label exit --msgbox "It can't be NULL,please configure again!" 15 60
         Status=2    
     else
         groupdel $group  > /tmp/.tmp 2>&1
         if [ `cat /tmp/.tmp | wc -l` -gt 0 ] ;then
            dialog --title "Delete Group" --textbox  /tmp/.tmp  20 80           
            Status=2
         else
            Status=2      
         fi
     fi
}

Pvshow()
{
       find /dev -name 'sd*' > /tmp/.diskinfo
       pvscan | awk  '!/Total/{print $2}' > /tmp/.pvinfo
       awk '!/da/{print $0}' /tmp/.diskinfo /tmp/.pvinfo | sort | uniq -u > /tmp/.diskex
       echo "===================PV Existing======================" > /tmp/.output
       pvscan | awk  '!/Total/{print $0}'| sort >> /tmp/.output
       echo "==================Unassigned Disks==================" >> /tmp/.output
       cat /tmp/.diskex | while read line
       do
           fdisk -l | grep $line | awk -F',' '{print $1}' >> /tmp/.output
       done     
}

PVShow()
{
       Pvshow
       dialog --title "Display Physical Volumn" --textbox  /tmp/.output  20 80  
}

LVShow()
{
       lvscan | awk -F"'" '{print $2 $3}' |  awk '$0=""NR". "$0' > /tmp/.output
       echo "===================LV Detail======================" >> /tmp/.output         
       lvdisplay | awk '!/All/{print $0}' | awk '!/#/{print $0}' | awk '!/UUID/{print $0}' | awk '!/- current/{print $0}' | awk '!/Read/{print $0}' | awk '!/Block/{print $0}' |awk '!/Segments/{print $0}'>> /tmp/.output
       dialog --title "Display Logical Volumn" --textbox  /tmp/.output  20 80
}

PVCShow()
{
       Pvshow
       dialog --title "Display PV Information" --exit-label Continue --textbox  /tmp/.output  20 80    
}

VGEShow()
{
       Pvshow
       echo "===================VG Existing======================" >> /tmp/.output      
       vgs >> /tmp/.output
       dialog --title "Display PV&VG Information" --exit-label Continue --textbox  /tmp/.output  20 80    
}

LVEShow()
{
       echo "===================VG Existing======================" > /tmp/.output  
       vgs >> /tmp/.output
       echo "===================LV Existing======================" >> /tmp/.output         
       lvscan | awk -F"'" '{print $2 $3}' |  awk '$0=""NR". "$0' >> /tmp/.output
       dialog --title "Display VG&LV Information" --exit-label Continue --textbox  /tmp/.output  20 80
}

PVCreate()
{
  PVCShow  
  dialog --title "Create Physical Volumn" --form "Please input the infomation for creating a new PV:" 15 60 2  \
  "Name of the new PV: /dev/" 1  1 "" 1  26  40  0     2>/tmp/.tmp
  result=$?
  if [ $result -eq 1 ] || [ $result -eq 255 ] ;then
       Status=3
  else
       pv=$(awk 'NR==1{print}' /tmp/.tmp)
       if [ ! $pv ];then
          dialog --title "Create Physical Volumn" --ok-label exit --msgbox "It can't be NULL,please configure again!" 15 60 
          Status=3   
       else           
          pvcreate /dev/$pv  > /dev/null 2>&1
          PVShow
          Status=3 
       fi
   fi         
}

VGCreate()
{
   PVCShow   
   dialog --title "Create Volumn Group" --form "Please input the infomation for creating a new LV:" 15 60 2  \
   "Name of the PV created: /dev/" 1  1 "" 1  30  40  0  \
   "Name of the new VG:       vg_" 2  1 "" 2  30  40  0     2>/tmp/.tmp
   result=$?
   if [ $result -eq 1 ] || [ $result -eq 255 ] ;then
       Status=3
   else
       pv=$(awk 'NR==1{print}' /tmp/.tmp)
       vg=$(awk 'NR==2{print}' /tmp/.tmp)
       if [ ! $vg ] || [ ! $pv ];then
          dialog --title "Create Volumn Group" --ok-label exit --msgbox "It can't be NULL,please configure again!" 15 60 
          Status=3   
       elif [ `grep $pv /tmp/.output | wc -l` -eq 0 ] ;then
          dialog --title "Create Volumn Group" --ok-label exit --msgbox "PV's name is wrong ,please configure again!" 15 60 
          Status=3
       else                  
          vgcreate vg_$vg /dev/$pv  > /tmp/.tmp 2>&1
          dialog --title "Create Volumn Group" --textbox  /tmp/.tmp  20 80          
          Status=3
       fi   
   fi   
}

VGExtend()
{
   VGEShow
   dialog --title "Extend Volumn Group" --form "Please input the infomation for creating a new LV:" 15 60 2  \
   "Name of the PV created: /dev/" 1  1 "" 1  30  40  0  \
   "Name of the VG existing:  vg_" 2  1 "" 2  30  40  0     2>/tmp/.tmp
   result=$?
   if [ $result -eq 1 ] || [ $result -eq 255 ] ;then
       Status=3
   else
       pv=$(awk 'NR==1{print}' /tmp/.tmp)
       vg=$(awk 'NR==2{print}' /tmp/.tmp)
       if [ ! $vg ] || [ ! $pv ];then
          dialog --title "Extend Volumn Group" --ok-label exit --msgbox "It can't be NULL,please configure again!" 15 60 
          Status=3   
       elif [ `grep $pv /tmp/.output | wc -l` -eq 0 ] || [ `grep $vg /tmp/.output | wc -l` -eq 0 ] ;then
          dialog --title "Extend Volumn Group" --ok-label exit --msgbox "PV or VG's name is wrong ,please configure again!" 15 60 
          Status=3
       else                      
          vgextend vg_$vg /dev/$pv  > /tmp/.tmp 2>&1
          dialog --title "Extend Volumn Group" --textbox  /tmp/.tmp  20 80              
          Status=3
       fi    
   fi 
}

LVCreate()
{
   LVEShow
   dialog --title "Create Logical Volumn" --form "Please input the infomation for creating a new LV:" 15 60 3  \
   "Name of existing VG: vg_" 1  1 "" 1  25  40  0  \
   "Name of the new LV:  lv_" 2  1 "" 2  25  40  0  \
   "Size(G,M) of the new LV:" 3  1 "" 3  25  40  0    2>/tmp/.tmp
   result=$?
   if [ $result -eq 1 ] || [ $result -eq 255 ] ;then
       Status=3
   else
       vgname=$(awk 'NR==1{print}' /tmp/.tmp)
       lvname=$(awk 'NR==2{print}' /tmp/.tmp)
       csize=$(awk 'NR==3{print}' /tmp/.tmp)          
       if [ ! $vgname ] || [ ! $lvname ] || [ ! $csize ] ;then
          dialog --title "Create Logical Volumn" --ok-label exit --msgbox "It can't be NULL,please configure again!" 15 60 
          Status=3   
       elif [ `grep $vgname /tmp/.output | wc -l` -eq 0 ] || [ `grep $lvname /tmp/.output | wc -l` -gt 0 ];then
          dialog --title "Create Volumn Group" --ok-label exit --msgbox "VG's name is wrong or LV exists ,please configure again!" 15 60 
          Status=3
       else                 
          lvcreate -L $csize -n lv_$lvname vg_$vgname  > /dev/null 2>&1
          mkfs.ext4 /dev/vg_$vgname/lv_$lvname  > /dev/null 2>&1
          mkdir /$lvname
          mount /dev/vg_$vgname/lv_$lvname /$lvname  > /dev/null 2>&1
          echo "/dev/vg_$vgname/lv_$lvname          /$lvname          ext4      defaults     0 0"   >> /etc/fstab
          Checkmount
          Status=3   
       fi
   fi       
}

LVExtend()
{
   LVEShow
   dialog --title "Ereate Logical Volumn" --form "Please input the infomation for creating a new LV:" 15 60 3  \
   "Name of existing VG: vg_" 1  1 "" 1  25  40  0  \
   "LV will be extended: lv_" 2  1 "" 2  25  40  0  \
   "Size(G,M) need increase:" 3  1 "" 3  25  40  0    2>/tmp/.tmp
   result=$?
   if [ $result -eq 1 ] || [ $result -eq 255 ] ;then
       Status=3
   else
       vgname=$(awk 'NR==1{print}' /tmp/.tmp)
       lvname=$(awk 'NR==2{print}' /tmp/.tmp)
       esize=$(awk 'NR==3{print}' /tmp/.tmp) 
       if [ ! $vgname ] || [ ! $lvname ] || [ ! $esize ] ;then
          dialog --title "Extend Logical Volumn" --ok-label exit --msgbox "It can't be NULL,please configure again!" 15 60 
          Status=3   
       elif [ `grep $vgname /tmp/.output | wc -l` -eq 0 ] || [ `grep $lvname /tmp/.output | wc -l` -eq 0 ] ;then
          dialog --title "Extend Logical Volumn" --ok-label exit --msgbox "VG or LV's name is wrong ,please configure again!" 15 60 
          Status=3
       else
          lvextend -L +$esize /dev/vg_$vgname/lv_$lvname  > /dev/null 2>&1
          resize2fs /dev/vg_$vgname/lv_$lvname  > /dev/null 2>&1
          Checkmount
          Status=3
       fi
   fi
}

Checkmount()
{
       df -Th > /tmp/.output
       dialog --title "Check Mount"  --textbox  /tmp/.output 20 80
}

NeedContinue()
{
       if [ $Status -eq 0 ]
          then Main
       elif [ $Status -eq 1 ]
          then Network
       elif [ $Status -eq 2 ]
          then User
       elif [ $Status -eq 3 ]
          then LVM
       fi
}

Network()
{
               NetOPTION=$(dialog --title "Configure Network" --menu "Choose your option" 15 60 2 \
               "1" "Configure Network" \
               "2" "Show interface brief"  3>&1 1>&2 2>&3)
               result=$?
               if [ $result -eq 1 ] || [ $result -eq 255 ] ;then
                    Status=0
               else   
                   case $NetOPTION in
                          "1")
                              ConfigNetwork
                          ;;
                          "2")    
                              InterBrief
                              Status=1
                          ;;
                          esac
                          NeedContinue
               fi    
}

User()
{
               UserOPTION=$(dialog --title "Set Group/User" --menu "Choose your option" 15 60 5 \
               "1" "Add group/user" \
               "2" "Only Add user" \
               "3" "Change User group" \
               "4" "Delete user" \
               "5" "Delete group"      3>&1 1>&2 2>&3)
               result=$?
               if [ $result -eq 1 ] || [ $result -eq 255 ] ;then
                    Status=0
               else   
                   case $UserOPTION in
                          "1")
                              GroupAdd
                          ;;
                          "2")    
                              UserAdd
                          ;;
                          "3")    
                              UserMod
                          ;;
                          "4")    
                              UserDel
                          ;;
                          "5")    
                              GroupDel                                                                                          
                          ;;
                          esac
                          NeedContinue        
               fi  
}

LVM()
{
               LVMOPTION=$(dialog --title "Configure LVM" --menu "Choose your option" 15 60 7 \
               "1" "Display Physical Volumn"\
               "2" "Display Logical Volumn" \
               "3" "Create Physical Volumn" \
               "4" "Create Volumn Group" \
               "5" "Extend Volumn Group" \
               "6" "Create Logical Volumn" \
               "7" "Extend Logical Volumn"         3>&1 1>&2 2>&3)
               result=$?
               if [ $result -eq 1 ] || [ $result -eq 255 ] ;then
                    Status=0
               else   
                   case $LVMOPTION in
                          "1")
                              PVShow
                              Status=3
                          ;;
                          "2")    
                              LVShow
                              Status=3
                          ;;
                          "3")
                              PVCreate
                          ;;
                          "4")
                              VGCreate
                          ;;
                          "5")
                              VGExtend
                          ;;
                          "6")
                              LVCreate
                          ;;
                          "7")
                              LVExtend
                          ;;
                          esac
                          NeedContinue          
               fi   
}

Main()
{
              FirstMenu
              exitstatus=$?
              if [ $exitstatus -eq 1 ] || [ $exitstatus -eq 255 ] ;then
                  exit 0
              else   
                  case $OPTION in
                     "1")
                             Network       
                     ;;
                     "2")
                             Hostname
                     ;;
                     "3")
                             UserPass
                     ;;
                     "4")
                             User
                     ;;
                     "5")
                             LVM
                     ;;
                  esac
                  NeedContinue
              fi
}
Main
