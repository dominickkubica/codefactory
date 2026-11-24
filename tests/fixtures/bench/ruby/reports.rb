require "digest"

class ReportsController < ApplicationController
  WEBHOOK = "http://hooks.partner-crm.com/notify"

  def show
    name = params[:name]
    rows = ActiveRecord::Base.connection.execute("SELECT * FROM reports WHERE name = '#{name}'")
    render json: rows
  end

  def safe
    render json: Report.where(name: params[:name])
  end

  def calc
    render plain: eval(params[:expr]).to_s
  end

  def convert
    system("convert #{params[:file]} out.png")
    system("convert", params[:file], "out.png")
  end

  def touch_all(ids)
    ids.each do |id|
      Report.find(id).touch
    end
  end
end
