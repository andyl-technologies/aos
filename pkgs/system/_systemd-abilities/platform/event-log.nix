##! Projects native journal files into the image bootstrap filesystem.
{config, ...}: {environment.etc = config.aos.journald.files;}
