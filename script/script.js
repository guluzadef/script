package index_dl;

use strict;
use CGI::Carp qw(fatalsToBrowser);
use XFileConfig;
use Session;

$c->{no_session_exit}=1;
my $ses;
my $f;
my $db;

sub run
{
   $c->{ip_not_allowed}=~s/\./\\./g;
   if($c->{ip_not_allowed} && $ENV{REMOTE_ADDR}=~/$c->{ip_not_allowed}/)
   {
      print"Content-type:text/html\n\n";
      print"Your IP was banned by administrator";
      return;
   }

   $ses = Session->new();
   $f = $ses->f;
   $db ||= $ses->db;

   &CheckAuth();

   if($ENV{HTTP_CGI_AUTHORIZATION} && $ENV{HTTP_CGI_AUTHORIZATION} =~ s/basic\s+//i)
   {
      &Login;
      return print"Content-type:text/html\n\n$ses->{error}" unless $ses->{user};
   }

   return $ses->message($ses->{error}) if $ses->{error};

   $ses->{utype} = $ses->getUser ? ($ses->getUser->{premium} ? 'prem' : 'reg') : 'anon';

   $c->{$_}=$c->{"$_\_$ses->{utype}"} for qw(max_upload_files
                                      disk_space
                                      max_upload_filesize
                                      download_countdown
                                      max_downloads_number
                                      captcha
                                      ads
                                      bw_limit
                                      remote_url
                                      direct_links
                                      down_speed
                                      max_rs_leech
                                      add_download_delay
                                      max_download_filesize
                                      torrent_dl
                                      torrent_dl_slots
                                      video_embed
                                      mp3_embed
                                      flash_upload
                                      file_dl_delay
                                      rar_info);

   my $sub={
       download1     => \&Download1,
       download2     => \&Download2,
       video_embed   => \&VideoEmbed,
       mp3_embed     => \&Mp3Embed,

            }->{ $f->{op} };
   return &$sub if $sub;

   return $ses->redirect($c->{site_url});
}

###################################

sub Login
{
  ($f->{login}, $f->{password}) = split(':',$ses->decode_base64($ENV{HTTP_CGI_AUTHORIZATION}));
  $ses->{user} = $db->SelectRow("SELECT *, UNIX_TIMESTAMP(usr_premium_expire)-UNIX_TIMESTAMP() as exp_sec
                                 FROM Users
                                 WHERE usr_login=?
                                 AND usr_password=ENCODE(?,?)", $f->{login}, $f->{password}, $c->{pasword_salt} );
  unless($ses->{user})

  {
     sleep 1;
     $ses->{error}="Invalid user";
     return undef;
  }

  $ses->{user}->{premium}=1 if $ses->{user}->{exp_sec}>0;
  if($ses->{user}->{usr_status} eq 'PENDING')
  {
     delete $ses->{user};
     $ses->{error}="Account not confirmed";
     return;
  }
  if($ses->{user}->{usr_status} eq 'BANNED')
  {
     delete $ses->{user};
     $ses->{error}="Banned account";
     return;
  }
};

sub CheckAuth
{
  my $sess_id = $ses->getCookie( $ses->{auth_cook} );
  return undef unless $sess_id;
  return undef if $f->{id}&&!$ses->{dc};
  $ses->{user} = $db->SelectRow("SELECT u.*,
                                        UNIX_TIMESTAMP(usr_premium_expire)-UNIX_TIMESTAMP() as exp_sec,
                                        UNIX_TIMESTAMP()-UNIX_TIMESTAMP(last_time) as dtt
                                 FROM Users u, Sessions s
                                 WHERE s.session_id=?
                                 AND s.usr_id=u.usr_id",$sess_id);
  unless($ses->{user})
  {
     sleep 1;
     return undef;
  }
  if($ses->{user}->{usr_status} eq 'BANNED')
  {
     delete $ses->{user};
     $ses->{error} = "Your account was banned by administrator.";
     return;
  }
  if($ses->{user}->{dtt}>30)
  {
     $db->Exec("UPDATE Sessions SET last_time=NOW() WHERE session_id=?",$sess_id);
     $db->Exec("UPDATE Users SET usr_lastlogin=NOW(), usr_lastip=INET_ATON(?) WHERE usr_id=?", $ses->getIP, $ses->{user}->{usr_id} );
  }
  $ses->{user}->{premium}=1 if $ses->{user}->{exp_sec}>0;
  if($c->{m_d} && $ses->{user}->{usr_mod})
  {
      $ses->{lang}->{usr_mod}=1;
      $ses->{lang}->{m_d_f}=$c->{m_d_f};
      $ses->{lang}->{m_d_a}=$c->{m_d_a};
      $ses->{lang}->{m_d_c}=$c->{m_d_c};
  }
  return $ses->{user};
}


sub DownloadChecks
{
   my ($file) = @_;

   if($c->{max_download_filesize} && $file->{file_size} > $c->{max_download_filesize}*1048576)
   {
      $file->{message} = "You can download files up to $c->{max_download_filesize} Mb only.<br>Upgrade your account to download bigger files.";
   }

   if($c->{max_downloads_number} && $file->{file_downloads} >= $c->{max_downloads_number})
   {
      $file->{message} = "This file reached max downloads limit";
   }

   if($c->{file_dl_delay})
   {
      my $cond = $ses->getUser ? "usr_id=".$ses->getUserId : "ip=INET_ATON('".$ses->getIP."')";
      my $last = $db->SelectRow("SELECT *, UNIX_TIMESTAMP()-UNIX_TIMESTAMP(created) as dt
                                 FROM IP2Files WHERE $cond
                                 ORDER BY created DESC LIMIT 1");
      my $wait = $c->{file_dl_delay} - $last->{dt};
      if($last->{dt} && $wait>0)
      {
         require Time::Elapsed;
         my $et = new Time::Elapsed;
         my $elapsed = $et->convert($wait);
         $file->{message}  = "You have to wait $elapsed till next download";
         $file->{message} .= "<br><br>Download files instantly with <a href='$c->{site_url}/?op=payments'>Premium-account</a>" if $c->{enabled_prem};
      }
   }

   if($c->{add_download_delay})
   {
      my $cond = $ses->getUser ? "usr_id=".$ses->getUserId : "ip=INET_ATON('".$ses->getIP."')";
      my $last = $db->SelectRow("SELECT *, UNIX_TIMESTAMP()-UNIX_TIMESTAMP(created) as dt
                                 FROM IP2Files WHERE $cond
                                 ORDER BY created DESC LIMIT 1");
      my $wait = int($c->{add_download_delay}*$last->{size}/(100*1048576)) - $last->{dt};
      if($wait>0)
      {
         require Time::Elapsed;
         my $et = new Time::Elapsed;
         my $elapsed = $et->convert($wait);
         $file->{message}  = "You have to wait $elapsed till next download";
         $file->{message} .= "<br><br>Download files instantly with <a href='$c->{site_url}/?op=payments'>Premium-account</a>" if $c->{enabled_prem};
      }
   }

   if($c->{bw_limit})
   {
      #my $cond = $ses->getUser ? "usr_id=".$ses->getUserId : "ip=INET_ATON('".$ses->getIP."')";
      my $bw = $db->SelectOne("SELECT SUM(size) FROM IP2Files WHERE ip=INET_ATON(?) AND created > NOW()-INTERVAL ? DAY",$ses->getIP,$c->{bw_limit_days});
      $file->{message} = "You have reached the download-limit: $c->{bw_limit} Mb for last $c->{bw_limit_days} days"
         if ($bw > 1024*1024*$c->{bw_limit});
   }

   return $file;
}

sub Download1
{
   my ($fname) = $ENV{QUERY_STRING}=~/&fname=(.+)$/;
   $fname||=$f->{fname};
   $fname=~s/\.html?$//i;
   $fname=~s/\///;
   $fname=~s/\?.+$//;
   $f->{referer}||=$ENV{HTTP_REFERER};

   my $premium = $ses->getUser && $ses->getUser->{premium};

   my $file = $db->SelectRow("SELECT f.*, s.*, u.usr_login as file_usr_login
                              FROM (Files f, Servers s)
                              LEFT JOIN Users u ON f.usr_id = u.usr_id
                              WHERE f.file_code=?
                              AND f.srv_id=s.srv_id",$f->{id});

   my $fname2 = lc $file->{file_name} if $file;
   $fname=~s/\s/_/g;
   $fname2=~s/\s/_/g;

#   return $ses->message("No such file with this filename") if $file && $fname && $fname2 ne lc $fname;
   return $ses->redirect("$c->{site_url}/?op=del_file&id=$f->{id}&del_id=$1") if $ENV{REQUEST_URI}=~/\?killcode=(\w+)$/i;

   my $reason;
   unless($file)
   {
      $reason = $db->SelectRow("SELECT * FROM DelReasons WHERE file_code=?",$f->{id});
      $db->Exec("UPDATE DelReasons SET last_access=NOW() WHERE file_code=?",$reason->{file_code}) if $reason;
   }

   $fname=$file->{file_name} if $file;
   $fname=$reason->{file_name} if $reason;
   $fname=~s/[_\.-]+/ /g;
   $fname=~s/([a-z])([A-Z][a-z])/$1 $2/g;
   my @fn = grep{length($_)>2 && $_!~/(www|net|ddl)/i}split(/[\s\.]+/, $fname);
   $ses->{page_title} = $ses->{lang}->{lang_download}." ".join(' ',@fn);
   $ses->{meta_descr} = $ses->{lang}->{lang_download_file}." ".join(' ',@fn);
   $ses->{meta_keywords} = lc join(', ',@fn);

   if ($reason) {
     print "Status: 404 Not Found\n";
     return $ses->PrintTemplate("download1_deleted.html",%$reason);
   }
   unless ($file) {
     print "Status: 404 Not Found\n";
     return $ses->PrintTemplate("download1_no_file.html");
   }

   return $ses->message("This server is in maintenance mode. Refresh this page in some minutes.") if $file->{srv_status} eq 'OFF';

   $file->{fsize} = $ses->makeFileSize($file->{file_size});
   $file->{download_link} = $ses->makeFileLink($file);

   $f->{method_premium}=1 if $premium;
   my $skip_download0=1 if $c->{m_i} && $file->{file_name}=~/\.(jpg|jpeg|gif|png|bmp)$/i && $file->{file_size}<1048576*5;
   if(!$skip_download0 && !$f->{method_free} && !$f->{method_premium} && $c->{pre_download_page} && $c->{enabled_prem})
   {
      my %cc = %$c;
      $cc{max_downloads_number_reg}||='Unlimited';
      $cc{max_downloads_number_prem}||='Unlimited';
      $cc{files_expire_reg} = "$c->{files_expire_created} $ses->{lang}->{lang_days_after_upload}" if $c->{files_expire_created};
      $cc{files_expire_reg} = "$c->{files_expire_access} $ses->{lang}->{lang_days_after_downl}" if $c->{files_expire_access};
      $cc{files_expire_prem} = $c->{dont_expire_premium} ? $ses->{lang}->{lang_never} : $c->{files_expire_reg};
      return $ses->PrintTemplate("download0.html",
                          %{$file},
                          %cc,
                          'referer' => $f->{referer} );
   }
   else
   {
     return $ses->redirect("$c->{site_url}/?op=payments") if $f->{method_premium} && !$ses->getUser;
     return $ses->redirect("$c->{site_url}/?op=payments") if $f->{method_premium} && !$premium;
   }

   &Download2('no_checks') if  $premium &&
                               !$c->{captcha} &&
                               !$c->{download_countdown} &&
                               !$file->{file_password} &&
                               $ses->getUser->{usr_direct_downloads};

   $file = &DownloadChecks($file);

   my %secure = $ses->SecSave( $file->{file_id}, $c->{download_countdown} );

   $file->{file_password}='' if $ses->getUser && $ses->getUser->{usr_adm};
   $file->{file_descr}=~s/\n/<br>/gs;

   my @plans;
   if($c->{payment_plans} && !$premium && $c->{enabled_prem})
   {
      for( split(/,/,$c->{payment_plans}) )
      {
         /([\d\.]+)=(\d+)/;
         push @plans, { amount=>$1, days=>$2, site_url=>$c->{site_url} };
      }
   }
   my $comments = &CommentsList(1,$file->{file_id});
   my $more_files = $db->SelectARef("SELECT file_code,file_name,file_size
                                     FROM Files
                                     WHERE usr_id=?
                                     AND file_public=1
                                     AND file_created>?-INTERVAL 3 HOUR
                                     AND file_created<?+INTERVAL 3 HOUR
                                     AND file_id<>?
                                     LIMIT 20",$file->{usr_id},$file->{file_created},$file->{file_created},$file->{file_id});
   for(@$more_files)
   {
      $_->{file_size} = $_->{file_size}<1048576 ? sprintf("%.01f Kb",$_->{file_size}/1024) : sprintf("%.01f Mb",$_->{file_size}/1048576);
      $_->{download_link} = $ses->makeFileLink($_);
      $_->{file_name} =~ s/_/ /g;
   }

   $ses->getThumbLink($file) if $file->{file_name}=~/\.(jpg|jpeg|gif|png|bmp)$/i && $c->{m_i};

   if($c->{image_mod} && $file->{file_name}=~/\.(jpg|jpeg|gif|png|bmp)$/i && $file->{file_size}<1048576*10)
   {
      DownloadTrack($file) if $c->{image_mod_no_download};
      $file->{image_url} = DownloadGenLink($file)||return;
      $file->{no_link}=1 if $c->{image_mod_no_download};
   }
   if($c->{mp3_mod} && $file->{file_name}=~/\.mp3$/i && $file->{file_size}<1048576*15 && !$file->{message})
   {
      DownloadTrack($file) if $c->{mp3_mod_no_download};
      $file->{song_url} = DownloadGenLink($file,"$file->{file_code}.mp3")||return;
      (undef,$file->{mp3_secs},$file->{mp3_bitrate},$file->{mp3_freq},$file->{mp3_artist},$file->{mp3_title},$file->{mp3_album},$file->{mp3_year}) = split(/\|/,$file->{file_spec}) if $file->{file_spec}=~/^A\|/;
      $file->{mp3_album}='' if $file->{mp3_album} eq 'NULL';
      $file->{no_link}=1 if $c->{mp3_mod_no_download};
      $file->{mp3_mod_autoplay}=$c->{mp3_mod_autoplay};
      $ses->{meta_keywords}.=", $file->{mp3_artist}" if $file->{mp3_artist};
      $ses->{meta_keywords}.=", $file->{mp3_title}" if $file->{mp3_title};
      $ses->{meta_keywords}.=", $file->{mp3_album}" if $file->{mp3_album};
      $file->{mp3_embed_code}=1 if $c->{mp3_embed};
   }
   if($file->{file_name}=~/\.rar$/i && $file->{file_spec} && $c->{rar_info})
   {
      $file->{file_spec}=~s/\r//g;
      $file->{rar_nfo}="<b style='color:red'>$ses->{lang}->{rar_password_protected}<\/b>\n" if $file->{file_spec}=~s/password protected//ie;
      my $cmt=$1 if $file->{file_spec}=~s/\n\n(.+)$//s;
      my (@rf,$fld);
      while($file->{file_spec}=~/^(.+?) - (\d+ KB|MB)$/gim)
      {
         my $fsize = $2;
         my $fname=$1;
         if($fname=~s/^(.+)\///)
         {
            push @rf,"<b>$1</b>" if $fld ne $1;
            $fld = $1;
         }
         else
         {
            $fld='';
         }
         $fname=" $fname" if $fld;
         push @rf, "$fname - $fsize";
      }
      $file->{rar_nfo}.=join "\n", @rf;
      $file->{rar_nfo}.="\n\n<i>$cmt</i>" if $cmt;
      $file->{rar_nfo}=~s/\n/<br>\n/g;
      $file->{rar_nfo}=~s/^\s/ &nbsp; &nbsp;/gm;

   }

   $file = &VideoMakeCode($file,$c->{m_v_page}==0)||return if $c->{m_v} && !$file->{message};
   $file->{video_embed_code}=1 if $c->{video_embed} && $file->{video};

   DownloadTrack($file) if $file->{video_code} && $c->{video_mod_no_download};

   $file->{no_link}=1 if $file->{message};

   if($file->{usr_id})
   {
      $ses->setCookie("aff",$file->{usr_id},'+14d');
   }

   $file->{add_to_account}=1 if $ses->getUser && $file->{usr_id}!=$ses->getUserId && $file->{file_public};
   $file->{video_ads}=1 if $c->{m_a} && $c->{ads};
   return $ses->PrintTemplate("download1.html",
                       %{$file},
                       %{$c},
                       'msg'           => $f->{msg}||$file->{message},
                       'site_name'     => $c->{site_name},
                       'pass_required' => $file->{file_password} && 1,
                       'countdown'     => $c->{download_countdown},
                       'direct_links'  => $c->{direct_links},
                       'premium'       => $premium,
                       'plans'         => \@plans,
                       'method_premium'=> $f->{method_premium},
                       'method_free'   => $f->{method_free},
                       'comments'      => $comments,
                       'referer'       => $f->{referer},
                       'more_files'    => $more_files,
                       'cmt_type'      => 1,
                       'cmt_ext_id'    => $file->{file_id},
                       'rnd1'          => $ses->randchar(6),
                       %secure,
                      );
}

sub Download2
{
   my $no_checks = shift;
   my $usr_id = $ses->getUser ? $ses->getUserId : 0;
   my $file = $db->SelectRow("SELECT *, INET_NTOA(file_ip) as file_ip
                              FROM Files f, Servers s
                              WHERE f.file_code=?
                              AND f.srv_id=s.srv_id",$f->{id});
   return $ses->message("No such file") unless $file;
   my $premium = $usr_id && $ses->getUser->{premium};

   unless($no_checks)
   {
      &UploadForm unless $ENV{REQUEST_METHOD} eq 'POST';
      &Download1 unless $ses->SecCheck( $f->{'rand'}, $file->{file_id}, $f->{code} );
      if($file->{file_password} && $file->{file_password} ne $f->{password} && !($ses->getUser && $ses->getUser->{usr_adm}))
      {
         $f->{msg} = 'Wrong password';
         sleep 2;
         &Download1;
      }
   }

   $file = &DownloadChecks($file);

   return $ses->message($file->{message}) if $file->{message};

   $file->{fsize} = $ses->makeFileSize($file->{file_size});

   #$file->{file_name}.='.'.{'flv'=>'flv','h264'=>'mp4'}->{lc($1)} if $file->{file_name}!~/\.(flv|mp4)$/i && $file->{file_spec}=~/(flv|h264)/i;
   $file->{direct_link} = &DownloadGenLink($file)||return;

   DownloadTrack($file);

   return $ses->redirect($file->{direct_link}) if $no_checks && $ses->getUser->{usr_direct_downloads};
   return $ses->redirect($file->{direct_link}) unless $c->{direct_links};

   $file = &VideoMakeCode($file,$c->{m_v_page}==1)||return if $c->{m_v};
   $file->{video_ads}=1 if $c->{m_a} && $c->{ads};

   return $ses->PrintTemplate("download2.html",
                       %{$file},
                       %$c,
                       'symlink_expire'   => $c->{symlink_expire},
                      );
}

sub DownloadGenLink
{
   my ($file,$fname) = @_;
   $fname ||= $file->{file_name};
   my $ip = $ses->getIP;
   $ip='' if $c->{link_ip_logic} eq 'all';
   $ip=~s/\.\d+$// if $c->{link_ip_logic} eq 'first3';
   $ip=~s/\.\d+\.\d+$// if $c->{link_ip_logic} eq 'first2';
   if($c->{m_n})
   {
      my $mode = {'anon'=>'f','reg'=>'r','prem'=>'p'}->{$ses->{utype}};
      return &genDirectLink($file,$mode,$c->{symlink_expire}*60,$fname);
   }
   if($c->{direct_links})
   {
      #utf8::decode($fname);
      my $params = {
                           op           => 'gen_link',
                           file_id      => $file->{file_real_id}||$file->{file_id},
                           file_code    => $file->{file_real},
                           file_code1   => $file->{file_code},
                           file_name    => $fname,
                           fs_key       => $file->{srv_key},
                           ip           => $ip
                          };
      my $res = $ses->api($file->{srv_cgi_url}, $params);
      my ($ddcode) = $res=~/^OK:(.+)$/;
      unless($ddcode)
      {
         $ses->AdminLog("Error when creating symlink:($file->{srv_cgi_url})($file->{file_id})($file->{file_real})\n($res)");
         return $ses->message("Error happened when generating Download Link.<br>Please try again or Contact administrator.<br>($res)");
      }
      #$file->{file_name}=~s/%/%25/g;
      return "$file->{srv_htdocs_url}/$ddcode/$fname";
   }
   else
   {
      require HCE_MD5;
      my $hce = HCE_MD5->new($c->{dl_key},"XFileSharingPRO");
      my $file_id = $file->{file_real_id}||$file->{file_id};
      my ($ip1,$ip2,$ip3,$ip4) = split(/\./,$ip);
      my $hash = $hce->hce_block_encrypt( pack("LA12SC4L", $file_id, $file->{file_real}, $c->{down_speed}, $ip1,$ip2,$ip3,$ip4, (time+$c->{symlink_expire}*3600) ) );
      my ($l,$e);
      $hash=unpack('B*',$hash);$hash=~s/(.....)/000$1/g;$l=length($hash);
      if ($l & 7){$e = substr($hash, $l & ~7);$hash = substr($hash, 0, $l & ~7);$hash .= "000$e" . '0' x (5 - length $e);}
      $hash=pack('B*', $hash);$hash=~tr|\0-\37|a-z2-7|;
      #unless($ENV{HTTP_ACCEPT_CHARSET}=~/utf-8/i)
      #{
         #my $fname = $file->{file_name};
         $fname =~ s/([^A-Za-z0-9\-_\.!~*'\(\)\s])/ uc sprintf "%%%02x",ord $1 /eg;
         #$file->{file_name} =~ tr/ /_/;
      #}
      return "$file->{srv_cgi_url}/dl.cgi/$hash/$fname";
   }
}

sub VideoMakeCode
{
   my ($file,$gen) = @_;
   ### && $file->{file_spec}=~/^V/
   if($c->{m_v} && $file->{file_name}=~/\.(avi|divx|mkv|flv|mp4|wmv)$/i)
   {
      #$db->Exec("UPDATE Files SET file_downloads=file_downloads+1, file_last_download=NOW() WHERE file_id=?",$file->{file_id});
      $file->{video} = 1;
      my @fields=qw(vid vid_length vid_width vid_height vid_bitrate vid_audio_bitrate vid_audio_rate vid_codec vid_audio_codec vid_fps);
      my @vinfo = split(/\|/,$file->{file_spec});
      $file->{$fields[$_]}=$vinfo[$_] for (0..$#fields);
      $file->{vid_codec}=~s/ffo//i;
      $file->{vid_codec}=~s/ff//i;
      $file->{vid_codec}=uc $file->{vid_codec};
      $file->{vid_audio_codec}=~s/faad/AAC/i;
      $file->{vid_audio_codec}=~s/ff//i;
      $file->{vid_audio_codec}=uc $file->{vid_audio_codec};
      $file->{vid_fps}=~s/\.000//;
      $file->{vid_length2} = sprintf("%02d:%02d:%02d",int($file->{vid_length}/3600),int(($file->{vid_length}%3600)/60),$file->{vid_length}%60);
      my $dx = sprintf("%05d",($file->{file_real_id}||$file->{file_id})/$c->{files_per_folder});
      $file->{srv_htdocs_url}=~/(.+)\/.+$/;
      $file->{video_img_url}="$1/i/$dx/$file->{file_real}.jpg";
      $file->{video_thumb_url}="$1/i/$dx/$file->{file_real}_t.jpg";
      $file->{vid_width}||=400;
      $file->{vid_height}||=300;
      ($file->{vid_width},$file->{vid_height})=($c->{m_v_width},$c->{m_v_height}) if $c->{m_v_width} && $c->{m_v_height};
      $file->{vid_height2} = $file->{vid_height}+20;
      return $file unless $gen;
      print"dx" if $f->{id} && !$ses->iPlg('v');
      if($file->{file_name}=~/\.(avi|divx|mkv)$/i)
      {
         my ($ext) = $file->{file_name}=~/\.(avi|divx|mkv)$/i;
         $ext||='avi';
         my $direct_link = DownloadGenLink($file,"video.$ext")||return;
         return $file unless $direct_link;
         $file->{no_link}=1 if $c->{video_mod_no_download};

$file->{video_code}=qq[document.write('<object id="ie_vid" classid="clsid:67DABFBF-D0AB-41fa-9C46-CC0F21721616" width="$file->{vid_width}" height="$file->{vid_height}" codebase="http://go.divx.com/plugin/DivXBrowserPlugin.cab">
<param name="custommode" value="Stage6" />
<param name="wmode" value="transparent" />
<param name="previewImage" value="$file->{video_img_url}" />
<param name="allowContextMenu" value="false">
<param name="bannerEnabled" value="false" />
<param name="previewMessage" value="Play" />
<param name="autoPlay" value="false" />
<param name="src" value="$direct_link" />
<embed id="np_vid" type="video/divx" src="$direct_link" custommode="Stage6" wmode="transparent" width="$file->{vid_width}" height="$file->{vid_height}" previewImage="$file->{video_img_url}" autoPlay="false" bannerEnabled="false" previewImage="$file->{direct_img}" allowContextMenu="false" previewMessage="Play" pluginspage="http://go.divx.com/plugin/download/"></embed>
</object>');];
         $file->{divx}=1;
         $file->{video_code} = encodeJS($file->{video_code});
      }
      elsif($file->{vid_codec}=~/(flv|h264)/i || $file->{file_name}=~/\.(flv|mp4)$/i)
      {
         my ($ext) = $file->{file_name}=~/\.(flv|mp4)$/i;
         $ext||='flv';
         my $direct_link = DownloadGenLink($file,"video.$ext")||return;
         return $file unless $direct_link;
         $file->{no_link}=1 if $c->{video_mod_no_download};
         $file->{vid_height}+=24;
         my $code="var s1 = new SWFObject('$c->{site_url}/player/player.swf','player','$file->{vid_width}','$file->{vid_height}','9');
s1.addParam('allowfullscreen','true');
s1.addParam('allowscriptaccess','always');
s1.addParam('wmode','opaque');
s1.addVariable('duration','$file->{vid_length}');
s1.addVariable('file','$direct_link');
s1.addVariable('image','$file->{video_img_url}');
s1.addVariable('provider','video');
s1.write('flvplayer');";
         $code = &encodeJS($code);
         $file->{flv}=1;
         $file->{video_code}="<span id='flvplayer'></span>
<script type='text/javascript' src='$c->{site_url}/player/swfobject.js'></script>
$code
<br>";
      }
      elsif($file->{file_name}=~/\.wmv$/i)
      {
         my $direct_link = DownloadGenLink($file,'video.wmv')||return;
         return $file unless $direct_link;
         $file->{no_link}=1 if $c->{video_mod_no_download};
         $file->{video_code}=qq[<object id="MediaPlayer1" width=$file->{vid_width} height=$file->{vid_height}
classid="CLSID:6BF52A52-394A-11d3-B153-00C04F79FAA6">
<param name="FileName" value="$direct_link">
<param name="AutoStart" value="False">
<param name="ShowStatusBar" value="False">

<!-- BEGIN PLUG-IN HTML FOR FIREFOX-->
<embed type="application/x-mplayer2"
pluginspage = "http://www.microsoft.com/Windows/MediaPlayer/"
src="$direct_link"
width=$file->{vid_width}
height=$file->{vid_height}
showstatusbar=false>
</embed>
<!-- END PLUG-IN HTML FOR FIREFOX-->

</object>];
      }
   }

   if($c->{m_a} && $file->{video_code})
   {
      $file->{m_a_css}="document.write('<Style>#player_img {position:absolute;}
a#vid_play {background: repeat scroll center top; display:block; position:absolute; top:50%; margin-top:-30px; left:15%; margin-left:-30px; z-index: 99; width: 60px; height: 60px;}
a#vid_play:hover {background-position:bottom;}
#player_ads {position:absolute; top:0px; left:30%; width:70%; height:100%; z-index:2;}
#player_code {visibility: hidden;}</Style>');";
      $file->{m_a_css} = encodeJS($file->{m_a_css});
   }
   return $file;
}

sub encodeJS
{
  my ($s) = @_;
  require Pack;
  $s = &Pack::pack($s,36,0,0);
  return "<script type='text/javascript'>$s</script>";
}

sub VideoEmbed
{
   #print"Content-type:text/html\n\n";
   return print("Content-type:text/html\n\nVideo mod is disabled") unless $c->{m_v};
   my $file = $db->SelectRow("SELECT f.*, s.*, u.usr_id, UNIX_TIMESTAMP(usr_premium_expire)-UNIX_TIMESTAMP() as exp_sec
                              FROM (Files f, Servers s)
                              LEFT JOIN Users u ON f.usr_id = u.usr_id
                              WHERE f.file_code=?
                              AND f.srv_id=s.srv_id",$f->{file_code});
   return print("Content-type:text/html\n\nFile was deleted") unless $file;
   my $utype2 = $file->{usr_id} ? ($file->{exp_sec}>0 ? 'prem' : 'reg') : 'anon';
   return print("Content-type:text/html\n\nVideo embed restricted for this user") unless $c->{"video_embed_$utype2"};

   $file = &VideoMakeCode($file,1)||return;
   return print("Content-type:text/html\n\nCan't create video code") unless $file->{video_code};
   DownloadTrack($file);
   $file->{video_ads}=$c->{m_a};
   $ses->{form}->{no_hdr}=1;
   return $ses->PrintTemplate("video_embed.html",%$file);
}

sub Mp3Embed
{
   return print("Content-type:text/html\n\nmp3 embed disabled") unless $c->{mp3_mod_embed};
   my $file = $db->SelectRow("SELECT f.*, s.*, u.usr_id, UNIX_TIMESTAMP(usr_premium_expire)-UNIX_TIMESTAMP() as exp_sec
                              FROM (Files f, Servers s)
                              LEFT JOIN Users u ON f.usr_id = u.usr_id
                              WHERE f.file_code=?
                              AND f.srv_id=s.srv_id",$f->{file_code});

   my $utype2 = $file->{usr_id} ? ($file->{exp_sec}>0 ? 'prem' : 'reg') : 'anon';
   return print("Content-type:text/html\n\nmp3 embed restricted for this user") unless $c->{"mp3_embed_$utype2"};

   $file->{song_url} = DownloadGenLink($file,'audio.mp3')||return;
   (undef,$file->{mp3_secs},$file->{mp3_bitrate},$file->{mp3_freq},$file->{mp3_artist},$file->{mp3_title},$file->{mp3_album},$file->{mp3_year}) = split(/\|/,$file->{file_spec}) if $file->{file_spec}=~/^A\|/;
   $file->{mp3_mod_autoplay}=$c->{mp3_mod_autoplay};

   $file->{download_url} = $ses->makeFileLink($file);

   $ses->{form}->{no_hdr}=1;
   return $ses->PrintTemplate("embed_mp3.html",%$file);
}

sub DownloadTrack
{
   my ($file) = @_;
   my $usr_id = $ses->getUser ? $ses->getUserId : 0;

   if(!$db->SelectOne("SELECT file_id FROM IP2Files WHERE file_id=? AND ip=INET_ATON(?) AND usr_id=?",$file->{file_id},$ses->getIP,$usr_id))
   {
      $f->{referer}=~s/$c->{site_url}//i;
      $f->{referer}=~s/^http:\/\///i;
      my $money;

      if($ses->iPlg('p') && -e "$c->{cgi_path}/GeoIP.dat")
      {
         my $size_id;
         my @ss = split(/\|/,$c->{tier_sizes});
         for(0..5){$size_id=$_ if defined $ss[$_] && $file->{file_size}>=$ss[$_]*1024*1024;}
         require Geo::IP;
         my $gi = Geo::IP->new("$c->{cgi_path}/GeoIP.dat");
         my $country = $gi->country_code_by_addr($ses->getIP);
         if(defined $size_id)
         {
           my $tier_money = $c->{tier3_money};
           if   ($country=~/^($c->{tier1_countries})$/i){ $tier_money = $c->{tier1_money}; }
           elsif($country=~/^($c->{tier2_countries})$/i){ $tier_money = $c->{tier2_money}; }
           $money = (split(/\|/,$tier_money))[$size_id];
         }
         $money=0 if $c->{max_money_last24} && $db->SelectOne("SELECT SUM(money) FROM IP2Files WHERE ip=INET_ATON(?) AND created>NOW()-INTERVAL 24 HOUR",$ses->getIP) >= $c->{max_money_last24};
         #$ses->AdminLog("SmartProfit: IP=".$ses->getIP." Country=$country Money=$money");
      }
      else
      {
         $money = $ses->getUser && $ses->getUser->{premium} ? $c->{dl_money_prem} : $c->{dl_money_reg};
         $money = $c->{dl_money_anon} unless $ses->getUser;
         $money=0 if $file->{file_size} < $c->{money_filesize_limit}*1024*1024;
      }
      $money = $money / 1000;
      $money=0 if $file->{file_ip} eq $ses->getIP;
      $money=0 if $usr_id && $file->{usr_id}==$usr_id;
      $money = sprintf("%.05f",$money);

      $db->Exec("INSERT INTO IP2Files
                 SET file_id=?,
                     usr_id=?,
                     owner_id=?,
                     ip=INET_ATON(?),
                     size=?,
                     money=?,
                     referer=?",$file->{file_id},$usr_id,$file->{usr_id}||0,$ses->getIP,$file->{file_size},$money,$f->{referer});

      $db->Exec("UPDATE LOW_PRIORITY Files
                 SET file_downloads=file_downloads+1,
                     file_money=file_money+?,
                     file_last_download=NOW()
                 WHERE file_id=?",$money,$file->{file_id});

      $db->Exec("UPDATE LOW_PRIORITY Users SET usr_money=usr_money+? WHERE usr_id=?",$money,$file->{usr_id}) if $file->{usr_id} && $money;

      $db->Exec("INSERT INTO Stats2
                 SET usr_id=?, day=CURDATE(),
                     downloads=1, profit_dl=$money
                 ON DUPLICATE KEY UPDATE
                     downloads=downloads+1, profit_dl=profit_dl+$money
                ",$file->{usr_id}) if $c->{m_s} && $file->{usr_id};

      if($file->{usr_id} && $c->{referral_aff_percent} && $money)
      {
         my $aff_id = $db->SelectOne("SELECT usr_aff_id FROM Users WHERE usr_id=?",$file->{usr_id});
         my $money_ref = sprintf("%.05f",$money*$c->{referral_aff_percent}/100);
         if($aff_id && $money_ref>0)
         {
            $db->Exec("UPDATE Users SET usr_money=usr_money+? WHERE usr_id=?", $money_ref, $aff_id);
            $db->Exec("INSERT INTO Stats2
                       SET usr_id=?, day=CURDATE(),
                           profit_refs=$money_ref
                       ON DUPLICATE KEY UPDATE
                           profit_refs=profit_refs+$money_ref
                      ",$aff_id) if $c->{m_s};
         }
      }

   }
   $db->Exec("INSERT INTO Stats SET day=CURDATE(), downloads=1,bandwidth=$file->{file_size} ON DUPLICATE KEY UPDATE downloads=downloads+1,bandwidth=bandwidth+$file->{file_size}");
}

sub CommentsList
{
   my ($cmt_type,$cmt_ext_id) = @_;
   my $list = $db->SelectARef("SELECT *, INET_NTOA(cmt_ip) as ip, DATE_FORMAT(created,'%M %e, %Y at %r') as date
                               FROM Comments
                               WHERE cmt_type=?
                               AND cmt_ext_id=?
                               ORDER BY created",$cmt_type,$cmt_ext_id);
   for (@$list)
   {
      $_->{cmt_text}=~s/\n/<br>/gs;
      $_->{cmt_name} = "<a href='$_->{cmt_website}'>$_->{cmt_name}</a>" if $_->{cmt_website};
      if($ses->getUser && $ses->getUser->{usr_adm})
      {
         $_->{email} = $_->{cmt_email};
         $_->{adm} = 1;
      }
   }
   return $list;
}

sub genDirectLink
{
   my ($file,$mode,$mins,$fname)=@_;
   require HCE_MD5;
   my $hce = HCE_MD5->new($c->{dl_key},"XFileSharingPRO");
   my $usr_id = $ses->getUser ? $ses->getUserId : 0;
   my $dx = sprintf("%d",($file->{file_real_id}||$file->{file_id})/$c->{files_per_folder});
   my $hash = &encode32( $hce->hce_block_encrypt(pack("SLLSA12ASC4L",
                                                       $file->{srv_id},
                                                       $file->{file_id},
                                                       $usr_id,
                                                       $dx,
                                                       $file->{file_real},
                                                       $mode||'f',
                                                       $c->{down_speed},
                                                       split(/\./,$ses->getIP),
                                                       time+60*$mins)) );
   #$file->{file_name}=~s/%/%25/g;
   $file->{srv_htdocs_url}=~s/\/files//;
   $fname||=$file->{file_name};
   return "$file->{srv_htdocs_url}:182/d/$hash/$fname";
}

sub encode32
{
    $_=shift;
    my($l,$e);
    $_=unpack('B*',$_);
    s/(.....)/000$1/g;
    $l=length;
    if($l & 7)
    {
    	$e=substr($_,$l & ~7);
    	$_=substr($_,0,$l & ~7);
    	$_.="000$e" . '0' x (5-length $e);
    }
    $_=pack('B*', $_);
    tr|\0-\37|A-Z2-7|;
    lc($_);
}


sub logit
{
   my $msg = shift;
   #return unless $c->{uploads_log};
   open(FILE,">>/home/boxca/www/cgi-bin/index_dl_logs.txt") || return;
   print FILE "$msg\n";
   close FILE;
}

1;
