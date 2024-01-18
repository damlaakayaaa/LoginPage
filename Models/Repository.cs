using Microsoft.EntityFrameworkCore;
using STB.MAP.UI.Utility;
using System;
using System.Linq;
using System.Linq.Expressions;

namespace STB.MAP.UI.Models

{
    public class Repository<T> : IRepository<T> where T : class
    {
        private readonly ApplicationDbContext _dbContext; 

        public Repository(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        }

        public IQueryable<T> GetAll(Expression<Func<T, bool>> filter = null, Func<IQueryable<T>, IOrderedQueryable<T>> orderBy = null, string includeProperties = "")
        {
            IQueryable<T> query = _dbContext.Set<T>();

            if (filter != null)
            {
                query = query.Where(filter);
            }

            foreach (var includeProperty in includeProperties.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                query = query.Include(includeProperty);
            }

            if (orderBy != null)
            {
                return orderBy(query);
            }
            else
            {
                return query;
            }
        }

        public T Get(Expression<Func<T, bool>> filter)
        {
            return _dbContext.Set<T>().FirstOrDefault(filter);
        }

        public void Ekle(T entity)
        {
            _dbContext.Set<T>().Add(entity);
        }

        public void Guncelle(T entity)
        {
            _dbContext.Set<T>().Update(entity);
        }

        public void Sil(T entity)
        {
            _dbContext.Set<T>().Remove(entity);
        }

        public void Kaydet()
        {
            _dbContext.SaveChanges();
        }
    }
}
