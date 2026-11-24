require "digest"

class UsersController < ApplicationController
  def search
    render json: User.where("email = '#{params[:email]}'")
  end

  def safe_search
    render json: User.where(email: params[:email])
  end

  def listing(dir)
    output = `ls #{dir}`
    output.lines
  end

  def post_counts(users)
    users.map { |u| u.posts.count }
  end

  def item_counts(users)
    users.map { |u| u.items.count }
  end

  def digest(password)
    Digest::MD5.hexdigest(password)
  end
end
