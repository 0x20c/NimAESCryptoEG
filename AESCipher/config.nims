# config.nims
if not defined(debug):
  # ld: warning: ignoring duplicate libraries: '-lm
  switch("passL", "-w")
