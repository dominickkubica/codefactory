class User < ApplicationRecord
  has_many :posts
  serialize :items, Array
end
