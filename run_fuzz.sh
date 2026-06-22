for t in percent_decode multipart normalize_path query flatten_json cookies form_body; do
  echo "== $t =="
  cargo fuzz run $t fuzz/seeds/$t -- -max_total_time=20 -timeout=5 || break
done
