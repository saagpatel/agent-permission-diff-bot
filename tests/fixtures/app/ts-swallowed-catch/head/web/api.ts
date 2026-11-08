export async function loadCart(id: string) {
  try {
    const res = await fetch(`/api/cart/${id}`);
    return res.json();
  } catch (e) {}
}

export async function saveCart(db: Db, cart: Cart) {
  await db.cart.upsert({ where: { id: cart.id }, update: cart, create: cart }).catch(() => {});
}
