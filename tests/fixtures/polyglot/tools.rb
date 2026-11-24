require "json"

class Report
  def build(ids)
    ids.each do |id|
      DB.query("SELECT 1")
    end
  end
end
