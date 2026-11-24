package com.shop;

import com.shop.Repo;

public class Orders {
  private Repo repo;

  public void load(java.util.List<Integer> ids) {
    for (int id : ids) {
      repo.findById(id);
    }
  }

  private int unusedHelper(int x) { return x * 3 + 1; }
}
